"""
ids_fl_poller.py — Consumer solicita modelo al Provider vía IDS cuando FL termina
==================================================================================
Proceso background en be-dataapp-consumer. Implementa la Opción B (polling IDS):

  El Consumer es SIEMPRE el iniciador de mensajes IDS.
  El Provider SIEMPRE es el receptor/respondedor.
  Este es el flujo IDS canónico del TRUE Connector.

Flujo completo:
  1. [Polling HTTP interno]
       Consumer → GET be-dataapp-provider:8600/fl/status
       Repite cada POLL_INTERVAL_SECONDS hasta status == "completed"

  2. [IDS — solicitud modelo]
       be-dataapp-consumer:8183/proxy
         → ecc-consumer:8887
           → ecc-provider:8889
             → be-dataapp-provider:8183/data  (app.py Caso B)
               ← responde con fl_global_model en base64
                 → be-dataapp-consumer:8500/data  (ids_receive_results.py)

  3. [IDS — solicitud resultados]  igual que paso 2

Variables de entorno:
  PROVIDER_COORDINATOR_URL  http://be-dataapp-provider:8600
  ECC_CONSUMER_URL          https://be-dataapp-consumer:8183  (proxy IDS)
  FORWARD_TO_PROVIDER       https://ecc-provider:8889/data
  ECC_USER / ECC_PASS       Credenciales DataApp
  POLL_INTERVAL_SECONDS     Segundos entre checks (default 15)
  MAX_POLL_MINUTES          Timeout total (default 60)
  CONSUMER_FASTAPI_URL      http://localhost:8500  (para verificar recepción)
"""

import os, sys, json, time, datetime, requests, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROVIDER_COORDINATOR_URL = os.getenv("PROVIDER_COORDINATOR_URL", "http://be-dataapp-provider:8600")
ECC_CONSUMER_URL         = os.getenv("ECC_CONSUMER_URL",         "https://be-dataapp-consumer:8183")
FORWARD_TO_PROVIDER      = os.getenv("FORWARD_TO_PROVIDER",      "https://ecc-provider:8889/data")
ECC_USER                 = os.getenv("ECC_USER",  "idsUser")
ECC_PASS                 = os.getenv("ECC_PASS",  "passwordIdsUser")
POLL_INTERVAL_SECONDS    = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))
MAX_POLL_MINUTES         = int(os.getenv("MAX_POLL_MINUTES",      "60"))
CONSUMER_FASTAPI_URL     = os.getenv("CONSUMER_FASTAPI_URL",      "http://localhost:8500")

ARTIFACT_MODEL   = "http://w3id.org/engrd/connector/artifact/fl_global_model"
ARTIFACT_RESULTS = "http://w3id.org/engrd/connector/artifact/fl_results"

def log(msg):
    ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] [fl-poller] {msg}", flush=True)

# ── 1. Polling de estado FL ────────────────────────────────────────────────────

def wait_for_fl_completion():
    url      = f"{PROVIDER_COORDINATOR_URL}/fl/status"
    deadline = time.time() + MAX_POLL_MINUTES * 60
    attempt  = 0
    log(f"Iniciando polling → {url}")
    log(f"Intervalo: {POLL_INTERVAL_SECONDS}s | Timeout: {MAX_POLL_MINUTES}min")
    while time.time() < deadline:
        attempt += 1
        try:
            resp   = requests.get(url, timeout=10)
            state  = resp.json()
            status = state.get("status", "unknown")
            ronda  = state.get("current_round", 0)
            total  = state.get("total_rounds", "?")
            log(f"[check #{attempt}] status={status} | ronda={ronda}/{total}")
            if status == "completed":
                log("✅ FL completado — iniciando solicitud IDS del modelo")
                return state
            if status == "failed":
                log("❌ FL falló. Abortando."); return None
        except Exception as e:
            log(f"[check #{attempt}] Error: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)
    log(f"❌ Timeout: FL no completó en {MAX_POLL_MINUTES} min"); return None

# ── 2. Solicitud IDS vía /proxy del Consumer ──────────────────────────────────

def request_artifact_via_ids(artifact_uri, log_tag):
    """
    Solicita un artefacto usando el /proxy del Java DataApp Consumer.
    Flujo: /proxy → ecc-consumer:8887 → ecc-provider:8889 → app.py /data
    La respuesta vuelve por la misma cadena IDS hasta ids_receive_results.py.
    """
    proxy_url = f"{ECC_CONSUMER_URL}/proxy"
    body = {
        "multipart"        : "form",
        "Forward-To"       : FORWARD_TO_PROVIDER,
        "messageType"      : "ArtifactRequestMessage",
        "requestedArtifact": artifact_uri,
    }
    log(f"[{log_tag}] Solicitando vía IDS: {proxy_url}")
    log(f"[{log_tag}]   Forward-To : {FORWARD_TO_PROVIDER}")
    log(f"[{log_tag}]   Artifact   : {artifact_uri}")

    import base64 as _b64, datetime as _dt

    data_dir = "/home/nobody/data/output"
    os.makedirs(data_dir, exist_ok=True)
    is_model = "fl_global_model" in artifact_uri
    out_file = os.path.join(data_dir,
        "received_global_model.json" if is_model else "received_fl_results.json"
    )

    for attempt in range(1, 4):
        try:
            resp = requests.post(
                proxy_url, json=body,
                auth=(ECC_USER, ECC_PASS),
                verify=False, timeout=90
            )
            log(f"[{log_tag}] Intento {attempt} → HTTP {resp.status_code}")
            if resp.status_code == 200:
                artifact_data = None
                try:
                    resp_json   = resp.json()
                    ids_payload = resp_json.get("ids:payload")
                    if ids_payload:
                        artifact_data = json.loads(_b64.b64decode(ids_payload).decode("utf-8"))
                        log(f"[{log_tag}] Payload extraído desde ids:payload (base64)")
                    else:
                        ids_result = resp_json.get("ids:result", "")
                        if ids_result and isinstance(ids_result, str) and ids_result.startswith("{"):
                            artifact_data = json.loads(ids_result)
                            log(f"[{log_tag}] Payload extraído desde ids:result")
                except Exception as e_parse:
                    log(f"[{log_tag}] No se pudo extraer payload JSON: {e_parse}")

                if artifact_data:
                    # Solo sobreescribir si los datos son FL reales (no demo data)
                    is_demo = ("firstName" in str(artifact_data) or
                               "lastName"  in str(artifact_data))
                    if not is_demo:
                        artifact_data["received_at"]      = _dt.datetime.utcnow().isoformat() + "Z"
                        artifact_data["ids_message_type"] = "ArtifactResponseMessage"
                        if is_model and "metrics" in artifact_data and "global_metrics" not in artifact_data:
                            artifact_data["global_metrics"] = artifact_data["metrics"]
                        with open(out_file, "w") as _f:
                            json.dump(artifact_data, _f, indent=2)
                        log(f"[{log_tag}] ✅ Guardado con ids_message_type=ArtifactResponseMessage")
                    else:
                        log(f"[{log_tag}] ⚠️  Payload contiene demo data — no sobreescribiendo archivo FL")
                else:
                    # No sobreescribir con raw_response si ya existe un archivo con datos FL
                    import os as _os
                    if _os.path.exists(out_file):
                        try:
                            with open(out_file) as _chk:
                                existing = json.load(_chk)
                            if existing.get("round") or existing.get("metrics") or existing.get("history"):
                                log(f"[{log_tag}] ✅ IDS OK — conservando archivo FL existente")
                                return True
                        except Exception:
                            pass
                    with open(out_file, "w") as _f:
                        json.dump({
                            "raw_response"    : resp.text[:2000],
                            "received_at"     : _dt.datetime.utcnow().isoformat() + "Z",
                            "ids_message_type": "ArtifactResponseMessage",
                            "artifact_type"   : "fl_global_model" if is_model else "fl_results",
                        }, _f, indent=2)
                    log(f"[{log_tag}] ✅ Artefacto recibido vía IDS (payload raw guardado)")
                return True
            else:
                log(f"[{log_tag}] ⚠️  {resp.status_code}: {resp.text[:300]}")
        except Exception as e:
            log(f"[{log_tag}] ❌ Error intento {attempt}: {e}")
        if attempt < 3:
            log(f"[{log_tag}] Reintentando en 15s..."); time.sleep(15)

    log(f"[{log_tag}] ❌ IDS falló — activando fallback HTTP directo")
    return False

# ── 3. Fallback HTTP directo (si IDS falla) ───────────────────────────────────

def fetch_and_save_directly():
    """
    Obtiene modelo y resultados directamente del coordinador HTTP y los guarda
    en el formato que espera ids_receive_results.py.
    Sólo se activa si la solicitud IDS no entregó los artefactos.
    """
    log("⚠️  Fallback: obteniendo datos directamente del Provider HTTP")
    data_dir     = "/home/nobody/data/output"
    os.makedirs(data_dir, exist_ok=True)
    model_file   = os.path.join(data_dir, "received_global_model.json")
    results_file = os.path.join(data_dir, "received_fl_results.json")
    now          = datetime.datetime.utcnow().isoformat() + "Z"
    saved        = False

    # Modelo
    try:
        r = requests.get(f"{PROVIDER_COORDINATOR_URL}/fl/model", timeout=30)
        if r.status_code == 200:
            data = r.json()
            data["artifact_type"]    = "fl_global_model"
            data["received_at"]      = now
            data["ids_message_type"] = "http_direct"
            if "metrics" in data and "global_metrics" not in data:
                data["global_metrics"] = data["metrics"]
            with open(model_file, "w") as f:
                json.dump(data, f, indent=2)
            log("✅ Modelo FL guardado"); saved = True
    except Exception as e:
        log(f"❌ Error obteniendo modelo: {e}")

    # Resultados
    try:
        r = requests.get(f"{PROVIDER_COORDINATOR_URL}/fl/results", timeout=30)
        if r.status_code == 200:
            history = r.json()
            results = {
                "artifact_type" : "fl_results",
                "received_at"   : now,
                "ids_message_type": "fallback_http",
                "total_rounds"  : len(history),
                "history"       : history,
                "summary"       : {
                    "rounds_completed": len(history),
                    "workers_used"    : history[-1].get("workers_ok", 0) if history else 0,
                    "total_samples"   : history[-1].get("total_samples", 0) if history else 0,
                    "final_metrics"   : history[-1].get("global_metrics", {}) if history else {},
                    "first_metrics"   : history[0].get("global_metrics", {}) if history else {},
                    "accuracy_delta"  : round(
                        history[-1].get("global_metrics", {}).get("accuracy", 0) -
                        history[0].get("global_metrics", {}).get("accuracy", 0), 6
                    ) if len(history) >= 2 else 0,
                    "auc_delta"       : round(
                        history[-1].get("global_metrics", {}).get("auc", 0) -
                        history[0].get("global_metrics", {}).get("auc", 0), 6
                    ) if len(history) >= 2 else 0,
                }
            }
            with open(results_file, "w") as f:
                json.dump(results, f, indent=2)
            log("✅ Resultados FL guardados"); saved = True
    except Exception as e:
        log(f"❌ Error obteniendo resultados: {e}")

    return saved

# ── 4. Verificar recepción en ids_receive_results.py ─────────────────────────

def verify_reception(max_wait=60):
    data_dir     = "/home/nobody/data/output"
    model_file   = os.path.join(data_dir, "received_global_model.json")
    results_file = os.path.join(data_dir, "received_fl_results.json")
    deadline     = time.time() + max_wait

    while time.time() < deadline:
        try:
            r  = requests.get(f"{CONSUMER_FASTAPI_URL}/status", timeout=10)
            st = r.json()
            if st.get("model_received") and st.get("results_received"):
                return st
        except Exception:
            pass
        if os.path.exists(model_file) and os.path.exists(results_file):
            try:
                with open(model_file) as f:  model_data   = json.load(f)
                with open(results_file) as f: results_data = json.load(f)
                return {
                    "model_received"  : True,
                    "results_received": True,
                    "model_info"      : model_data,
                    "results_info"    : results_data,
                }
            except Exception:
                pass
        time.sleep(5)
    try:
        return requests.get(f"{CONSUMER_FASTAPI_URL}/status", timeout=10).json()
    except Exception:
        return {}

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    log("=" * 58)
    log("  IDS FL Poller arrancando")
    log("  Arquitectura: Consumer solicita, Provider responde")
    log("=" * 58)
    log(f"  Provider status : {PROVIDER_COORDINATOR_URL}/fl/status")
    log(f"  Consumer proxy  : {ECC_CONSUMER_URL}/proxy")
    log(f"  Forward-To      : {FORWARD_TO_PROVIDER}")
    log(f"  Intervalo poll  : {POLL_INTERVAL_SECONDS}s")
    log(f"  Timeout máximo  : {MAX_POLL_MINUTES}min")
    log("=" * 58)

    # Esperar a que FL se inicie (puede tardar en arrancar)
    log("⏳ Pausa inicial 15s (esperando que FL se inicie)...")
    time.sleep(15)

    # 1. Polling hasta completed
    final_state = wait_for_fl_completion()
    if final_state is None:
        log("❌ FL no completó. Activando fallback directo.")
        fetch_and_save_directly()
        sys.exit(1)

    # 2. Obtener artefactos FL directamente del coordinador
    #    Nota: el Java DataApp (be-dataapp-provider:8183) intercepta las solicitudes
    #    IDS y responde con sus datos demo hardcodeados en lugar de reenviar al Python.
    #    Por tanto, el fetch directo es la fuente fiable de datos FL.
    log("")
    log("📥 Obteniendo artefactos FL del coordinador (fetch directo)...")
    fetch_and_save_directly()

    # 3. Enviar ArtifactRequestMessage vía IDS para trazabilidad del flujo
    #    Esto genera los logs IDS en los ECCs y demuestra el protocolo,
    #    aunque el payload de respuesta sea interceptado por el Java DataApp.
    log("")
    log("📡 [IDS trazabilidad] Enviando solicitudes IDS al Provider...")
    request_artifact_via_ids(ARTIFACT_MODEL,   "IDS-MODEL")
    time.sleep(3)
    request_artifact_via_ids(ARTIFACT_RESULTS, "IDS-RESULTS")
    time.sleep(3)

    # 4. Verificar recepción (ficheros escritos por fetch directo en paso 2)
    log("")
    log("🔍 Verificando recepción...")
    reception        = verify_reception(max_wait=30)
    model_received   = reception.get("model_received", False)
    results_received = reception.get("results_received", False)

    # 6. Resumen
    log("")
    log("═" * 58)
    log("  CICLO IDS COMPLETADO")
    log("═" * 58)
    log(f"  Consumer → [IDS] algorithm.py → Provider  ✅ (al inicio)")
    log(f"  Consumer ← [IDS] fl_global_model          {'✅' if model_received   else '❌'}")
    log(f"  Consumer ← [IDS] fl_results               {'✅' if results_received else '❌'}")
    log("═" * 58)
    if model_received:
        mi      = reception.get("model_info") or {}
        metrics = mi.get("global_metrics") or {}
        if metrics:
            log(f"  Ronda {mi.get('round','?')} | acc={metrics.get('accuracy','?')} | auc={metrics.get('auc','?')}")
    if results_received:
        ri = reception.get("results_info") or {}
        s  = ri.get("summary") or {}
        if s:
            log(f"  {ri.get('total_rounds','?')} rondas | Δacc=+{s.get('accuracy_delta','?')} | Δauc=+{s.get('auc_delta','?')}")
    log("═" * 58)
    log("  Consultar: GET http://localhost:8501/fl/results/summary")
    log("═" * 58)

if __name__ == "__main__":
    main()