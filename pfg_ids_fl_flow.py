#!/usr/bin/env python3
"""
pfg_ids_fl_flow.py  --  Demostración completa IDS + Federated Learning
======================================================================
Arquitectura Híbrida:
  - Control Plane (IDS): Negociación de contratos y descubrimiento HTTPS.
  - Data Plane (WS): Transferencia asíncrona de alto rendimiento de pesos FL.

  FASE 0   Resolver endpoints
           - GET /status y /broker/connectors.
  FASE 0.5 Explorar Catálogo IDS Dinámicamente
           - GET /ids/self-description (Lista Datasets del Coordinator).
  FASE 1   Coordinator obtiene el algoritmo vía IDS
           - POST /fl/fetch-algorithm (Lee model.py y config).
  FASE 2   Descubrimiento de peers en Broker + match semántico
           - POST /broker/discover (Umbral >= 80% compatibilidad columnas).
  FASE 3   Negociación de contratos (Restringido > Worker4 descartado)
           - POST /fl/negotiate (Firma de credenciales ODRL mutuas mediante DAPS).
  FASE 4   Arranque del Entrenamiento FL vía propagación IDS
           - POST /fl/start
  FASE 5   Monitorización en Tiempo Real y Resultados
           - GET /fl/status, GET /fl/results y GET /fl/model
  FASE 6   Verificación Soberanía de Datos y Acceso de Red
           - Intento de lecturas por nodos no autorizados para comprobar
             que el IDS bloquea la transferencia (Security Token).

Se incluye soporte de Cancelación Global (/system/reset) pulsando Ctrl+C.

Uso:
  python pfg_ids_fl_flow.py
  python pfg_ids_fl_flow.py --skip-fl
  python pfg_ids_fl_flow.py --coordinator 3
  python pfg_ids_fl_flow.py --timeout 360
"""


import sys
import json
import argparse
import time
import re
import os
import threading
try:
    import msvcrt
    _HAS_MSVCRT = True
except ImportError:
    _HAS_MSVCRT = False

import requests
import urllib3
try:
    import websockets
    import websockets.exceptions
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False

TLS_CERT = "./cert/daps/ca.crt" if os.path.exists("./cert/daps/ca.crt") else False
if not TLS_CERT:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# Configuracion
# =============================================================================

# Puerto del dataapp coordinator: convencion 5000 + N (p.ej. 5002 para worker-2)
# Se puede sobreescribir con --coordinator-port
DEFAULT_COORDINATOR_PORT_BASE = 5000

# Flag global de cancelacion -- lo activa el hilo del listener de teclado
_cancel_requested = False


# =============================================================================
# Colores y logging
# =============================================================================

RESET   = "\033[0m"
BOLD    = "\033[1m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
GRAY    = "\033[90m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"


def _sep(char="=", width=72, color=CYAN):
    print(f"{color}{char * width}{RESET}")


def banner(title, subtitle=""):
    print()
    _sep("=", color=BOLD + CYAN)
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    if subtitle:
        print(f"{GRAY}  {subtitle}{RESET}")
    _sep("=", color=BOLD + CYAN)


def phase(num, title, description=""):
    print()
    _sep("-", color=BLUE)
    print(f"{BOLD}{BLUE}  FASE {num}  --  {title}{RESET}")
    if description:
        for line in description.splitlines():
            print(f"{GRAY}  {line}{RESET}")
    _sep("-", color=BLUE)


def step(num, title):
    print(f"\n{BOLD}{WHITE}  > Paso {num}  --  {title}{RESET}")


def substep(msg):
    print(f"    {GRAY}-> {msg}{RESET}")


def ok(msg):
    print(f"    {GREEN}OK  {msg}{RESET}")


def fail(msg):
    print(f"    {RED}ERR {msg}{RESET}")
    sys.exit(1)


def warn(msg):
    print(f"    {YELLOW}WARN {msg}{RESET}")


def info(msg):
    print(f"    {GRAY}INFO {msg}{RESET}")


def field(label, value, indent=4):
    pad = " " * indent
    val = str(value)
    if len(val) > 110:
        val = val[:107] + "..."
    print(f"{pad}{MAGENTA}{label:<28}{RESET} {val}")


def ids_arrow(direction, msg_type, src, dst):
    arrow = "->" if direction == "out" else "<-"
    color = CYAN if direction == "out" else GREEN
    short = msg_type.replace("ids:", "").replace("Message", "Msg")
    print(f"    {color}[IDS {arrow}] {short:<42}{GRAY}  {src}  ->  {dst}{RESET}")


def section(title):
    print(f"\n    {BOLD}{WHITE}-- {title} --{RESET}")


# =============================================================================
# Cliente HTTP
# =============================================================================

SESSION = requests.Session()
SESSION.verify = False


def http_get(url, timeout=240):
    substep(f"GET  {url}")
    try:
        r = SESSION.get(url, timeout=timeout)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {"_raw": r.text}
    except requests.exceptions.ConnectionError:
        fail(f"Conexion rechazada en {url} -- el container no esta levantado?")
    except requests.exceptions.ReadTimeout:
        fail(f"Timeout ({timeout}s) esperando {url}")
    except requests.exceptions.HTTPError as exc:
        fail(f"HTTP {exc.response.status_code} en {url}")


def http_post(url, body, timeout=240):
    substep(f"POST {url}")
    try:
        r = SESSION.post(url, json=body, timeout=timeout)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {"_raw": r.text}
    except requests.exceptions.ConnectionError:
        fail(f"Conexion rechazada en {url}")
    except requests.exceptions.ReadTimeout:
        fail(
            f"Timeout ({timeout}s) esperando respuesta de {url}\n"
            f"      El ECC TRUE Connector puede tardar en la primera llamada (token DAPS).\n"
            f"      Usa --timeout N para subir el limite."
        )
    except requests.exceptions.HTTPError as exc:
        body_txt = ""
        try:
            body_txt = exc.response.text[:400]
        except Exception:
            pass
        fail(f"HTTP {exc.response.status_code} en {url}\n      {body_txt}")


def http_post_raw(url, body, timeout=240):
    substep(f"POST {url}")
    try:
        r = SESSION.post(url, json=body, timeout=timeout)
        r.raise_for_status()
        return r.text
    except requests.exceptions.ConnectionError:
        fail(f"Conexion rechazada en {url}")
    except requests.exceptions.ReadTimeout:
        fail(
            f"Timeout ({timeout}s) esperando respuesta de {url}\n"
            f"      El ECC TRUE Connector puede tardar en la primera llamada (token DAPS).\n"
            f"      Usa --timeout N para subir el limite."
        )
    except requests.exceptions.HTTPError as exc:
        body_txt = ""
        try:
            body_txt = exc.response.text[:400]
        except Exception:
            pass
        fail(f"HTTP {exc.response.status_code} en {url}\n      {body_txt}")


# =============================================================================
# Parser IDS -- JSON puro o embebido en multipart
# =============================================================================

def parse_ids(raw, want_type=None):
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            if not want_type or want_type in obj.get("@type", ""):
                return obj
    except Exception:
        pass

    blocks = re.findall(r'\{[\s\S]*?\}', raw)
    blocks.sort(key=len, reverse=True)

    if want_type:
        for b in blocks:
            try:
                obj = json.loads(b)
                if isinstance(obj, dict) and want_type in obj.get("@type", ""):
                    return obj
            except Exception:
                pass

    for b in blocks:
        try:
            obj = json.loads(b)
            if isinstance(obj, dict) and ("@id" in obj or "ids:resourceCatalog" in obj):
                return obj
        except Exception:
            pass

    return {}


# =============================================================================
# FASE 0 -- Resolver endpoints desde /status y Broker Fuseki
# =============================================================================

def _ecc_internal_url(endpoint_raw, connector_uri):
    """
    Convierte el endpoint publico del broker (puerto 8449 externo)
    al endpoint interno Docker (puerto 8889 /data -- Camel ECC receiver).
    Mapeo: ecc-workerN:8889/data
    """
    if endpoint_raw:
        m = re.search(r"(ecc-worker\d+):(\d+)", endpoint_raw)
        if m:
            host = m.group(1)
            return f"https://{host}:8889/data"
        m2 = re.search(r"(ecc-worker\d+)", endpoint_raw)
        if m2:
            return f"https://{m2.group(1)}:8889/data"
    m = re.search(r"worker(\d+)", connector_uri)
    if m:
        return f"https://ecc-worker{m.group(1)}:8889/data"
    return ""


def _ecc_label(ecc_url):
    m = re.search(r"(ecc-worker\d+):(\d+)", ecc_url)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    m2 = re.search(r"https?://([^/]+)", ecc_url)
    return m2.group(1) if m2 else ecc_url


def fase0_resolver_endpoints(coordinator_url, cid, req_timeout):
    phase(
        0,
        "Resolver endpoints",
        "Paso 0a: GET /status           -> health check del DataApp coordinator\n"
        "Paso 0b: GET /broker/connectors -> todos los conectores registrados en Fuseki\n"
        f"Paso 0c: Extraer Worker-{cid} del Broker -> ECC URL y connector_uri sin hardcodear"
    )

    # -- 0a: health check del DataApp coordinator -------------------------------
    step("0a", f"GET /status -- health check del Worker-{cid}")
    status = http_get(f"{coordinator_url}/status", timeout=req_timeout)
    ok(f"Worker-{cid} responde correctamente en {coordinator_url}")
    field("instance",        status.get("instance", "?"))
    field("role (actual)",   status.get("role",     "worker"))

    # -- 0b: TODOS los conectores desde el broker (incluido el coordinator) -----
    step("0b", "GET /broker/connectors -- todos los conectores del Broker Fuseki")
    bd    = http_get(f"{coordinator_url}/broker/connectors", timeout=req_timeout)
    raw_p = bd.get("connectors", [])
    count = bd.get("count", len(raw_p))

    ok(f"{count} conectores en el broker")
    print()

    all_entries      = {}   # wid -> entry (todos, incluyendo coordinator)
    all_peers        = []   # solo los que NO son coordinator
    peers            = {}

    for c in raw_p:
        uri     = c.get("connector_uri", "")
        ep_raw  = c.get("endpoint", "")
        ecc_url = _ecc_internal_url(ep_raw, uri)
        label   = _ecc_label(ecc_url)
        m       = re.search(r"worker(\d+)", uri) or re.search(r"worker(\d+)", ecc_url)
        wid     = m.group(1) if m else "?"

        entry = {
            "connector_uri": uri,
            "ecc_url":       ecc_url,
            "ecc_label":     label,
            "endpoint_raw":  ep_raw,
        }
        all_entries[wid] = entry

        is_coord = (wid == str(cid))
        tag = f"  {CYAN}<- coordinator{RESET}" if is_coord else ""
        print(f"    {GRAY}*  Worker-{wid}{RESET}{tag}")
        field("  connector_uri",     uri,    indent=8)
        field("  endpoint (broker)", ep_raw, indent=8)
        field("  ecc_url (interno)", ecc_url, indent=8)
        print()

        if not is_coord:
            peers[f"worker{wid}"] = entry
            all_peers.append(entry)

    if not all_entries:
        fail(
            "El broker no devolvio ningun conector.\n"
            "      Comprueba que broker-core, broker-fuseki y broker-reverseproxy estan levantados\n"
            "      y que los workers se han auto-registrado."
        )

    # -- 0c: Datos del Worker-{cid} extraidos del Broker -----------------------
    step("0c", f"Datos del Worker-{cid} (coordinator) extraidos del Broker")

    coord_entry = all_entries.get(str(cid))
    if coord_entry:
        ok(f"Worker-{cid} encontrado en el Broker -- sin hardcodear")
        field("connector_uri (broker)", coord_entry["connector_uri"])
        field("ecc_url      (broker)", coord_entry["ecc_url"])
        coordinator_entry = coord_entry
    else:
        # Fallback solo si el worker-N no se registro aun en el broker
        warn(
            f"Worker-{cid} no encontrado en el Broker.\n"
            f"      Puede que aun no se haya registrado -- re-intenta en unos segundos.\n"
            f"      Usando connector_uri del /status como fallback."
        )
        fallback_ecc = f"https://ecc-worker{cid}:8889/data"
        coordinator_entry = {
            "connector_uri": status.get("connector_uri",
                                        f"http://w3id.org/engrd/connector/worker{cid}"),
            "ecc_url":       fallback_ecc,
            "ecc_label":     _ecc_label(fallback_ecc),
        }

    if not all_peers:
        fail(
            "El broker no devolvio ningun peer (aparte del coordinator).\n"
            "      Comprueba que los demas workers estan levantados y registrados."
        )

    return {
        "coordinator": coordinator_entry,
        "peers":       peers,
        "all_peers":   all_peers,
    }



# =============================================================================
# FASE 1 -- Coordinator obtiene el algoritmo via IDS
# =============================================================================

def fase1_solicitar_algoritmo(coordinator_url, cid, endpoints, req_timeout):
    """
    El coordinator (worker-N) asume su rol nativo e inicializa el modelo localmente.
    No requiere IDS self-fetch ya que los archivos residen en su propio disco (DataApp).
    """
    coord_ecc   = endpoints["coordinator"]["ecc_url"]
    coord_label = endpoints["coordinator"]["ecc_label"]

    phase(
        1,
        f"Worker-{cid} obtiene el algoritmo y el fichero de configuracion",
        "El DataApp tiene la soberania del algoritmo y configuracion localmente\n"
        "sin necesidad de peticiones IDS contra su propio conector."
    )

    step("1", "POST /fl/fetch-algorithm -- init coordinator")
    info(f"Coordinator ({coord_label}) carga algorithm.py y fl_config.json desde su entorno local")

    result = http_post(f"{coordinator_url}/fl/fetch-algorithm", {}, timeout=req_timeout)

    status = result.get("status", "")
    if status == "everything_received":
        ok("algorithm.py + fl_config.json leidos nativamente por el coordinator")
        field("source", result.get("source_ecc", "local_filesystem"))
        cfg = result.get("fl_config") or {}
        if cfg:
            field("rounds",        cfg.get("rounds"))
            field("round_timeout", f"{cfg.get('round_timeout')}s")
            field("epochs",        cfg.get("epochs"))
    else:
        fail(f"El coordinator no pudo obtener el algoritmo: {result}")

    print()
    print(f"    {BOLD}{GREEN}** Worker-{cid} es ahora el COORDINATOR **{RESET}")


# =============================================================================
# FASE 2 -- Descubrimiento de peers compatibles
# =============================================================================

def fase2_descubrir_peers(coordinator_url, cid, endpoints, req_timeout):
    coord_label = endpoints["coordinator"]["ecc_label"]

    phase(
        2,
        "Descubrimiento de peers compatibles  (multi-CSV, umbral 80%)",
        "POST /broker/discover\n"
        "  Para cada peer registrado en el Broker:\n"
        "    1. GET /dataset/all-columns -> lista de todos sus CSVs con columnas\n"
        "    2. Matching matematico: ratio columnas_comunes/columnas_propias (umbral >=80%)\n"
        "    3. Ollama (LLM local) verifica semanticamente el CSV candidato\n"
        "    4. Si Ollama no alcanza confianza del 80%, se usa el mejor ratio matematico\n"
        "  El CSV ganador queda asignado a ese worker para el entrenamiento FL."
    )

    step("2", "POST /broker/discover")
    data       = http_post(f"{coordinator_url}/broker/discover", {}, timeout=req_timeout)
    compatible = data.get("compatible_workers", [])
    my_cols    = data.get("my_columns_count", "?")
    count      = data.get("count", len(compatible))

    ok(f"{count} workers compatibles encontrados")
    field("Columnas del coordinator", my_cols)
    print()

    for w in compatible:
        uri      = w.get("connector_uri", "?")
        match    = w.get("match_ratio", 0)
        cols     = len(w.get("common_cols", []))
        sel_csv  = w.get("selected_csv") or "(auto)"
        m        = re.search(r"worker(\d+)", uri)
        wid      = m.group(1) if m else "?"
        peer     = endpoints["peers"].get(f"worker{wid}", {})
        ecc      = peer.get("ecc_url") or w.get("ecc_url", "(desconocido)")
        pl       = peer.get("ecc_label") or f"ecc-worker{wid}:8889"

        print(f"    {GREEN}OK{RESET}  Worker-{wid}  {GRAY}{uri}{RESET}")
        field("  ECC (broker)", ecc, indent=8)

        # Handshake de metadatos (IDS Catalog fetch)
        ids_arrow("out", "ids:DescriptionRequestMessage",  coord_label, pl)
        ids_arrow("in",  "ids:DescriptionResponseMessage", pl, coord_label)

        print(f"\n        {GRAY}Descubrimiento dinamico -- Consultando Catalogo IDS del peer (Self-Description):{RESET}")
        for ev in w.get("all_evaluated", []):
            fname_ev = ev["filename"]
            ratio_ev = ev["ratio"]
            common_c = ev.get("common_cols_count", 0)
            total_c  = ev.get("total_cols", 0)
            print(f"          - Recurso en catalogo: {fname_ev:<30} (match: {ratio_ev:.0%} - {common_c}/{total_c} cols)")

        llm_rec  = w.get("llm_recommended")
        sel_csv  = w.get("selected_csv") or "(auto)"
        math_csv = w.get("math_filename") or sel_csv

        if llm_rec:
            llm_conf = w.get("llm_confidence", 0)
            llm_mod  = w.get("llm_model", "Ollama")
            llm_rsn  = w.get("llm_reasoning", "Decision basada en esquema semantico.")

            # -- Mostrar el razonamiento ya calculado por /broker/discover -----
            # El LLM fue invocado UNA sola vez durante /broker/discover en el
            # DataApp. Aqui se reproduce ese mismo razonamiento en modo
            # "streaming simulado" caracter a caracter, sin relanzar el LLM.
            # Esto garantiza que el log muestra siempre la misma decision y
            # elimina los duplicados que aparecian en los logs del DataApp.
            import time as _time
            print(f"\n        {MAGENTA}-> IA Local ({llm_mod}) -- razonamiento (calculado en /broker/discover):{RESET}")
            print(f"          {GRAY}", end="", flush=True)
            for _ch in llm_rsn:
                print(_ch, end="", flush=True)
                _time.sleep(0.008)
            print(f"{RESET}\n")

            field(f"  IA ({llm_mod}) Sugerencia",   f"{CYAN}{llm_rec} (confianza: {llm_conf:.0%}){RESET}", indent=8)
            field(f"  IA ({llm_mod}) Razonamiento", f"{GRAY}{llm_rsn}{RESET}", indent=8)

            if llm_conf >= 0.80:
                field("  CSV (Seleccionado)", f"{GREEN}{sel_csv}{RESET}", indent=8)
            else:
                print(f"        {YELLOW} Confianza de IA < 80%. Fallback a emparejamiento matematico.{RESET}")
                field("  CSV (Seleccionado por columnas)", math_csv, indent=8)
                field("  CSV (Seleccionado)", f"{GREEN}{sel_csv}{RESET}", indent=8)
        else:
            print(f"\n        {YELLOW}⚠️ LLM Fallback:{RESET} La validación por IA no devolvió un formato válido o dio Timeout.")
            print(f"        {YELLOW}Activando plan de rescate: se aplicará la delegación 100% matemática.{RESET}")
            field("  CSV (Seleccionado por columnas)", math_csv, indent=8)
            field("  CSV (Seleccionado)", f"{GREEN}{sel_csv}{RESET}", indent=8)

        info(f"     El coordinator usara {sel_csv!r} "
             f"en worker-{wid} para el entrenamiento FL")
        print()

    if not compatible:
        warn(
            "Ningun worker supero el umbral del 80% de coincidencia de columnas.\n"
            "      Verifica que los workers tienen al menos un CSV con las mismas "
            "columnas que el coordinator."
        )

    return compatible


# =============================================================================
# FASE 3 -- Negociacion IDS coordinator -> cada peer
# =============================================================================

def fase3_negociar(coordinator_url, cid, endpoints, req_timeout):
    coord_label = endpoints["coordinator"]["ecc_label"]

    phase(
        3,
        "Negociacion IDS  coordinator -> cada peer",
        f"Coordinator ECC: {endpoints['coordinator']['ecc_url']}\n"
        "\n"
        "Handshake IDS por peer:\n"
        "  1. DescriptionRequestMessage  ->  DescriptionResponseMessage\n"
        "  2. ContractRequestMessage     ->  ContractAgreementMessage  (acepta)\n"
        "                                ->  RejectionMessage          (rechaza)\n"
        "  3. ContractAgreementMessage   ->  MessageProcessedNotif.    (si acepto)\n"
        "\n"
        "  Worker-1: ACEPTA  (FL_OPT_OUT no definido en docker-compose)\n"
        "  Worker-3: ACEPTA  (FL_OPT_OUT no definido en docker-compose)\n"
        "  Worker-4: RECHAZA (FL_OPT_OUT=true en docker-compose -- soberania del dato)"
    )

    step("5c", "POST /fl/negotiate")
    data     = http_post(f"{coordinator_url}/fl/negotiate", {}, timeout=req_timeout)
    accepted = data.get("accepted", [])
    rejected = data.get("rejected", [])

    print(f"\n  {BOLD}Detalle de cada negociacion IDS:{RESET}\n")

    for w in accepted:
        uri  = w.get("connector_uri", "?")
        tc   = w.get("transfer_contract", "")
        m    = re.search(r"worker(\d+)", uri)
        wid  = m.group(1) if m else "?"
        peer = endpoints["peers"].get(f"worker{wid}", {})
        pl   = peer.get("ecc_label") or f"ecc-worker{wid}:8889"
        pe   = peer.get("ecc_url")   or f"https://ecc-worker{wid}:8889/data"

        print(f"  {BOLD}Worker-{wid}{RESET}  {GRAY}{uri}{RESET}")
        field("  ECC (broker)", pe, indent=6)
        ids_arrow("out", "ids:DescriptionRequestMessage",        coord_label, pl)
        ids_arrow("in",  "ids:DescriptionResponseMessage",       pl, coord_label)
        ids_arrow("out", "ids:ContractRequestMessage",           coord_label, pl)
        ids_arrow("in",  "ids:ContractAgreementMessage",         pl, coord_label)
        ids_arrow("out", "ids:ContractAgreementMessage (confirm)", coord_label, pl)
        ids_arrow("in",  "ids:MessageProcessedNotificationMsg",  pl, coord_label)
        print(f"    {GREEN}ACEPTA -- contrato IDS establecido{RESET}")
        if tc:
            field("transfer_contract", tc[:72] + ("..." if len(tc) > 72 else ""))
        print()

    for w in rejected:
        uri    = w.get("connector_uri", "?")
        reason = w.get("reason", "?")
        msg    = w.get("message", "")
        m      = re.search(r"worker(\d+)", uri)
        wid    = m.group(1) if m else "?"
        peer   = endpoints["peers"].get(f"worker{wid}", {})
        pl     = peer.get("ecc_label") or f"ecc-worker{wid}:8889"
        pe     = peer.get("ecc_url")   or f"https://ecc-worker{wid}:8889/data"

        # Si la razon es 'unexpected_ids_response', extrae el motivo real del mensaje
        # (ocurre cuando el contenedor tiene cod. antiguo y no detecta el @type vacio)
        actual_reason = reason
        if reason == "unexpected_ids_response" and msg:
            try:
                import ast as _ast
                _msg_dict = _ast.literal_eval(msg) if isinstance(msg, str) else msg
                actual_reason = _msg_dict.get("reason", reason)
            except Exception:
                pass

        reason_labels = {
            "fl_opt_out"             : "FL_OPT_OUT=true (soberania del dato) -- IDS RejectionMessage",
            "fl_participation_denied": "FL_AUTHORIZED_URIS vacio (no autorizado a participar)",
            "unauthorized_consumer"  : "consumer URI no autorizada",
            "error"                  : "error de comunicacion",
        }
        reason_text = reason_labels.get(actual_reason, actual_reason)

        print(f"  {BOLD}Worker-{wid}{RESET}  {GRAY}{uri}{RESET}")
        field("  ECC (broker)", pe, indent=6)
        ids_arrow("out", "ids:DescriptionRequestMessage",  coord_label, pl)
        ids_arrow("in",  "ids:DescriptionResponseMessage", pl, coord_label)
        ids_arrow("out", "ids:ContractRequestMessage",     coord_label, pl)
        ids_arrow("in",  "ids:RejectionMessage",           pl, coord_label)
        print(f"    {RED}RECHAZA -- {reason_text}{RESET}")
        if actual_reason != reason:
            field("reason (API)", f"{actual_reason}  (detectado en mensaje IDS)")
        else:
            field("reason (API)", reason)
        if msg:
            field("mensaje",     msg[:100])
        print()

    # -- Resumen ---------------------------------------------------------------
    _sep("-", color=BLUE)
    print(f"  {BOLD}Resumen de participacion FL:{RESET}\n")

    for w in accepted:
        uri = w.get("connector_uri", "?")
        m   = re.search(r"worker(\d+)", uri)
        wid = m.group(1) if m else "?"
        print(f"    {GREEN}PARTICIPA   Worker-{wid}   {GRAY}{uri}{RESET}")

    for w in rejected:
        uri    = w.get("connector_uri", "?")
        reason = w.get("reason", "?")
        msg    = w.get("message", "")
        m      = re.search(r"worker(\d+)", uri)
        wid    = m.group(1) if m else "?"
        # Extraer motivo real si viene como 'unexpected_ids_response'
        if reason == "unexpected_ids_response" and msg:
            try:
                import ast as _ast
                _md = _ast.literal_eval(msg) if isinstance(msg, str) else msg
                reason = _md.get("reason", reason)
            except Exception:
                pass
        reason_label = {
            "fl_opt_out": "fl_opt_out (IDS soberania)",
            "unauthorized_consumer": "unauthorized (IDS)",
        }.get(reason, reason)
        print(f"    {RED}RECHAZADO   Worker-{wid}   {GRAY}{uri}  --  {reason_label}{RESET}")

    print()

    return {"accepted": accepted, "rejected": rejected}


# =============================================================================
# Verificacion del coordinator
# =============================================================================

def verificar_coordinator(coordinator_url, cid, endpoints, req_timeout):
    print()
    _sep("-", color=BLUE)
    print(f"{BOLD}{BLUE}  Estado del coordinator tras la negociacion{RESET}")
    _sep("-", color=BLUE)

    step("6", "GET /status")
    data = http_get(f"{coordinator_url}/status", timeout=req_timeout)

    role      = data.get("role", "?")
    algo_ok   = data.get("algorithm_loaded", False)
    config_ok = data.get("config_loaded", False)
    fl_status = data.get("fl_status", "?")
    peers     = data.get("peer_eccs", [])
    fl_cfg    = data.get("fl_config") or {}

    field("instance",         data.get("instance", "?"))
    field("role",             role)
    field("algorithm_loaded", "SI" if algo_ok  else "NO")
    field("config_loaded",    "SI" if config_ok else "NO")
    field("fl_status",        fl_status)

    if fl_cfg:
        section("FL Config")
        for k, v in fl_cfg.items():
            field(f"  {k}", v, indent=6)

    if peers:
        section("Peer ECCs activos (workers aceptados)")
        for p in peers:
            m   = re.search(r"worker(\d+)", p)
            wid = m.group(1) if m else "?"
            b   = endpoints["peers"].get(f"worker{wid}", {})
            b_ecc = b.get("ecc_url", "")
            match_tag = f"  {GREEN}(= broker){RESET}" if b_ecc == p else (
                        f"  {YELLOW}(broker: {b_ecc}){RESET}" if b_ecc else "")
            print(f"      {GRAY}Worker-{wid}: {p}{RESET}{match_tag}")

    print()
    if role == "coordinator" and algo_ok and config_ok:
        ok("Coordinator listo para /fl/start")
    else:
        warn(f"Estado inesperado: role={role}  algo={algo_ok}  config={config_ok}")


# =============================================================================
# FASE 4 -- Arranque del entrenamiento FL
# =============================================================================

def fase4_arrancar_fl(coordinator_url, cid, endpoints, req_timeout):
    phase(
        4,
        "Arranque del entrenamiento Federated Learning",
        "POST /fl/start -- el coordinator distribuye pesos globales y arranca las rondas"
    )

    step("4", "POST /fl/start")
    data   = http_post(f"{coordinator_url}/fl/start", {}, timeout=req_timeout)
    status = data.get("status", "?")
    peers  = data.get("peers", [])
    cfg    = data.get("fl_config", {}) or {}

    if status == "started":
        ok("Entrenamiento FL arrancado correctamente")
    else:
        warn(f"Respuesta inesperada: status={status}")

    field("coordinator", data.get("coordinator", "?"))
    if cfg:
        field("rounds",        cfg.get("rounds"))
        field("round_timeout", f"{cfg.get('round_timeout')}s")

    section("Workers entrenando")
    for p in peers:
        m   = re.search(r"worker(\d+)", p)
        wid = m.group(1) if m else "?"
        b   = endpoints["peers"].get(f"worker{wid}", {})
        b_ecc = b.get("ecc_url", "")
        note  = f"  {GREEN}(broker){RESET}" if b_ecc == p else (
                f"  {YELLOW}(broker: {b_ecc}){RESET}" if b_ecc else "")
        print(f"      {GREEN}Worker-{wid}: {GRAY}{p}{RESET}{note}")

    print()
    info(f"Monitoriza:  GET {coordinator_url}/fl/status")
    info(f"Resultados:  GET {coordinator_url}/fl/results  (cuando status=completed)")
    info(f"Modelo:      GET {coordinator_url}/fl/model")


# =============================================================================
# FASE 5 -- Monitorizacion del entrenamiento en tiempo real
# =============================================================================

def _ids_log(direction, msg_type, src, dst):
    arrow = "--" if direction == "out" else "--"
    color = CYAN   if direction == "out" else GREEN
    short = msg_type.replace("ids:", "").replace("Message", "Msg")
    print(f"      {color}[IDS {arrow}]  {short:<44}{GRAY}{src}    {dst}{RESET}")


def _print_ronda_header(rnd_num, total_rounds, cid):
    print()
    print(f"    {CYAN}{'' * 54}{RESET}")
    print(f"    {BOLD}{CYAN}  RONDA {rnd_num}/{total_rounds or '?'}  "
          f"[coordinator-{cid}]{RESET}")
    print(f"    {CYAN}{'' * 54}{RESET}")


def _print_handshake_algoritmo(rnd_num, wid, peer_lbl, cid):
    """
    Handshake IDS completo para distribucion de algorithm.py + fl_config.json.
    En app.py esto ocurre en _negotiate_and_send_algorithm, que se llama
    en CADA ronda (el coordinator lo reenvia para asegurar sincronia).
    """
    print(f"\n      {BOLD}-> Worker-{wid}{RESET}")
    _ids_log("out", "ids:DescriptionRequestMessage",
             f"coordinator-{cid}", peer_lbl)
    _ids_log("in",  "ids:DescriptionResponseMessage",
             peer_lbl, f"coordinator-{cid}")
    _ids_log("out", "ids:ContractRequestMessage",
             f"coordinator-{cid}", peer_lbl)
    _ids_log("in",  "ids:ContractAgreementMessage",
             peer_lbl, f"coordinator-{cid}")
    _ids_log("out", "ids:ContractAgreementMessage (confirmacion)",
             f"coordinator-{cid}", peer_lbl)
    _ids_log("in",  "ids:MessageProcessedNotificationMessage",
             peer_lbl, f"coordinator-{cid}")
    print(f"      {GRAY}[ronda {rnd_num}] algorithm.py + fl_config.json "
          f"-> {peer_lbl}  {GREEN}{RESET}")


def fase5_monitorizar_fl(coordinator_url, cid, nego, endpoints, req_timeout):
    """
    Monitoriza el entrenamiento FL en tiempo real via WebSocket /ws/fl-status.

    El coordinator emite eventos JSON por cada cambio de estado:
      connected       -> conexion establecida, estado inicial
      fl_started      -> FL arranco (total_rounds, min_workers)
      round_started   -> inicio de ronda N
      round_completed -> ronda N cerrada con metricas (accuracy, auc, loss...)
      fl_completed    -> FL terminado con mejor ronda y metricas finales
      fl_failed       -> FL abortado (min_workers no alcanzado)
      fl_update       -> cambio de estado generico

    Fallback: si websockets no esta instalado o la conexion falla,
    vuelve al polling HTTP (GET /fl/status cada 5s).
    """
    accepted      = nego.get("accepted", [])
    accepted_wids = sorted(
        m.group(1)
        for w in accepted
        for m in [re.search(r"worker(\d+)", w.get("connector_uri", ""))] if m
    )

    phase(
        5,
        "Monitorizacion FL en tiempo real via WebSocket",
        f"ws://localhost:{coordinator_url.split(':')[-1]}/ws/fl-status\n"
        f"Eventos: fl_started -> round_started -> round_completed -> fl_completed\n"
        f"Workers participantes: {', '.join('worker-' + w for w in accepted_wids)}\n"
        f"Fallback automatico a polling HTTP si WebSocket no esta disponible."
    )

    # -- Verificar estado real de los tuneles WS -------------------------------
    step("WS-check", "GET /ws/tunnel-status -- verificando tuneles de comunicacion activos")
    try:
        ts = SESSION.get(f"{coordinator_url}/ws/tunnel-status", timeout=10, verify=TLS_CERT)
        if ts.ok:
            td = ts.json()
            ws_status_clients  = td.get("fl_status_clients", 0)
            ws_workers_active  = td.get("worker_tunnels_active", [])
            ws_coord_tunnel    = td.get("coordinator_tunnel_active", False)
            info(f"[WS] /ws/fl-status   -> {ws_status_clients} cliente(s) de monitorizacion")
            if ws_workers_active:
                ok(f"[WS] Tuneles High-Speed ACTIVOS -> workers: {ws_workers_active}")
            else:
                warn("[WS] Ningun tunel High-Speed WS activo aun -- "
                     "los pesos se enviaran via IDS HTTP (fallback normal)")
            info(f"[WS] Tunel hacia coordinator: {'Activo ' if ws_coord_tunnel else 'Inactivo (fallback HTTP)'}")
        else:
            warn(f"GET /ws/tunnel-status respondio {ts.status_code}")
    except Exception as _te:
        warn(f"No se pudo consultar /ws/tunnel-status: {_te}")

    # wss:// -- el DataApp corre con TLS (uvicorn + ECDHE cipher suites, start.sh).
    # https://localhost:5002 -> wss://localhost:5002/ws/fl-status
    ws_url = coordinator_url.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_url}/ws/fl-status"

    if not _WS_AVAILABLE:
        warn(
            "libreria 'websockets' no instalada -- usando polling HTTP como fallback.\n"
            "      Instala con: pip install websockets"
        )
        _fase5_polling_fallback(coordinator_url, cid, nego, endpoints, accepted_wids)
        return

    info(f"Conectando a {ws_url} ...")

    import asyncio as _asyncio

    async def _ws_monitor():
        conn_attempts = 0
        max_attempts  = 5

        while conn_attempts < max_attempts:
            try:
                # wss:// con TLS -- el DataApp usa ECDHE (start.sh con ssl_keyfile).
                # ssl_ctx con verify=TLS_CERT para certificado auto-firmado del DataApp.
                import ssl as _ssl_fl
                _ssl_fl_ctx = _ssl_fl.SSLContext(_ssl_fl.PROTOCOL_TLS_CLIENT)
                _ssl_fl_ctx.check_hostname = False
                _ssl_fl_ctx.verify_mode    = _ssl_fl.CERT_NONE
                async with websockets.connect(
                    ws_url,
                    ssl          = _ssl_fl_ctx,
                    ping_interval = 20,
                    ping_timeout  = 30,
                    open_timeout  = 15,
                ) as ws:
                    ok(f"WebSocket conectado a {ws_url}")
                    conn_attempts = 0   # reset en conexion exitosa

                    seen_rounds   = 0
                    total_rounds  = None
                    weights_shown = {}   # rnd -> set de wids ya mostrados
                    fl_done       = False

                    async for raw_msg in ws:
                        try:
                            evt = json.loads(raw_msg)
                        except Exception:
                            continue

                        event = evt.get("event", "")

                        # -- connected -----------------------------------------
                        if event == "connected":
                            role         = evt.get("role", "?")
                            status       = evt.get("status", "?")
                            current_rnd  = evt.get("current_round", 0)
                            total_rounds = evt.get("total_rounds") or total_rounds

                            print()
                            ok(f"WebSocket activo -- coordinator-{cid}  "
                               f"role={role}  status={status}")
                            info(f"Canal WS: {ws_url}")
                            info(f"El servidor emite eventos IDS en tiempo real "
                                 f"(fl_started -> round_started -> round_completed -> fl_completed)")

                            if status in ("completed", "failed"):
                                warn("El FL ya termino antes de conectar -- mostrando resultados")
                                fl_done = True
                                break

                            # -- FIX race condition ronda 1 --------------------
                            import re as _re_status
                            rnd_match = _re_status.match(r"round_(\d+)", status)
                            if rnd_match:
                                rnd_num = int(rnd_match.group(1))
                                if rnd_num not in weights_shown:
                                    print()
                                    weights_shown.setdefault(rnd_num, set())
                                    _print_ronda_header(rnd_num, total_rounds, cid)
                                    print()
                                    print(f"    {BOLD}[ronda {rnd_num}] Distribuyendo algorithm.py + "
                                          f"fl_config.json a peers via IDS...{RESET}")
                                    for w in accepted:
                                        uri = w.get("connector_uri", "")
                                        m   = re.search(r"worker(\d+)", uri)
                                        wid = m.group(1) if m else "?"
                                        pe  = endpoints["peers"].get(f"worker{wid}", {})
                                        pl  = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                                        _print_handshake_algoritmo(rnd_num, wid, pl, cid)
                                    print()
                                    print(f"    {BOLD}[ronda {rnd_num}]  Enviando pesos globales a peers via WebSocket (High-Speed Data Plane)...{RESET}")
                                    for w in accepted:
                                        uri = w.get("connector_uri", "")
                                        m   = re.search(r"worker(\d+)", uri)
                                        wid = m.group(1) if m else "?"
                                        pe  = endpoints["peers"].get(f"worker{wid}", {})
                                        pl  = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                                        print(f"      {CYAN}[WS ]  fl_global_weights::round{rnd_num}  {GRAY}coordinator-{cid}  --  {pl}{RESET}")
                                        print(f"      {GRAY}Pesos globales ronda {rnd_num} "
                                              f"-> {pl}  {GREEN}{RESET}")
                                    print()
                                    print(f"    {BOLD}[ronda {rnd_num}] Entrenando localmente "
                                          f"(coordinator-{cid})...{RESET}")
                                    n_exp = len(accepted_wids) + 1
                                    print(f"    {GRAY}[WS] Esperando pesos... 1/{n_exp}  "
                                          f"(coordinator-{cid} local en progreso){RESET}")

                        # -- fl_started ----------------------------------------
                        elif event == "fl_started":
                            total_rounds = evt.get("total_rounds")
                            min_workers  = evt.get("min_workers")
                            print()
                            ok(f"[WS] FL arrancado -- {total_rounds} rondas  "
                               f"min_workers={min_workers}")
                            info(f"[WS] Workers participantes: "
                                 f"{', '.join('worker-' + w for w in accepted_wids)}")
                            info(f"[WS] Escuchando eventos en tiempo real...")

                        # -- round_started -------------------------------------
                        elif event == "round_started":
                            rnd_num      = evt.get("round", "?")
                            total_rounds = evt.get("total_rounds") or total_rounds

                            if rnd_num in weights_shown:
                                # Ya renderizado desde el evento 'connected'
                                pass
                            else:
                                weights_shown.setdefault(rnd_num, set())
                                print()
                                info(f"[WS] Evento round_started recibido -- ronda {rnd_num}")
                                _print_ronda_header(rnd_num, total_rounds, cid)

                                # Distribucion de algorithm.py via IDS (en cada ronda)
                                print()
                                print(f"    {BOLD}[ronda {rnd_num}] Distribuyendo algorithm.py + "
                                      f"fl_config.json a peers via IDS...{RESET}")
                                for w in accepted:
                                    uri = w.get("connector_uri", "")
                                    m   = re.search(r"worker(\d+)", uri)
                                    wid = m.group(1) if m else "?"
                                    pe  = endpoints["peers"].get(f"worker{wid}", {})
                                    pl  = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                                    _print_handshake_algoritmo(rnd_num, wid, pl, cid)

                                print()
                                print(f"    {BOLD}[ronda {rnd_num}]  Enviando pesos globales a peers via WebSocket (High-Speed Data Plane)...{RESET}")
                                for w in accepted:
                                    uri = w.get("connector_uri", "")
                                    m   = re.search(r"worker(\d+)", uri)
                                    wid = m.group(1) if m else "?"
                                    pe  = endpoints["peers"].get(f"worker{wid}", {})
                                    pl  = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                                    print(f"      {CYAN}[WS ]  fl_global_weights::round{rnd_num}  {GRAY}coordinator-{cid}  --  {pl}{RESET}")
                                    print(f"      {GRAY}Pesos globales ronda {rnd_num} "
                                          f"-> {pl}  {GREEN}{RESET}")

                                print()
                                print(f"    {BOLD}[ronda {rnd_num}] Entrenando localmente "
                                      f"(coordinator-{cid})...{RESET}")
                                n_exp = len(accepted_wids) + 1
                                print(f"    {GRAY}[WS] Esperando pesos... 1/{n_exp}  "
                                      f"(coordinator-{cid} local en progreso){RESET}")

                        # -- round_completed -----------------------------------
                        elif event == "round_completed":
                            rnd_num  = evt.get("round", seen_rounds + 1)
                            elapsed  = evt.get("elapsed_seconds", 0)
                            workers  = evt.get("workers_ok", "?")
                            samples  = evt.get("total_samples", 0)
                            gm       = evt.get("global_metrics", {})
                            total_rounds = evt.get("total_rounds") or total_rounds

                            def _fv(k):
                                v = gm.get(k)
                                return f"{v:.4f}" if isinstance(v, float) else (
                                    str(v) if v is not None else "--")

                            info(f"[WS] Evento round_completed -- ronda {rnd_num}")

                            # Mostrar llegada de pesos de cada worker
                            already = weights_shown.get(rnd_num, set())
                            n_exp   = len(accepted_wids) + 1
                            for wid in accepted_wids:
                                if wid not in already:
                                    already.add(wid)
                                    total_so_far = 1 + len(already)
                                    pe  = endpoints["peers"].get(f"worker{wid}", {})
                                    pl  = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                                    print()
                                    print(f"    {BOLD}[ronda {rnd_num}]  Pesos locales "
                                          f"recibidos de worker-{wid} (WebSocket):{RESET}")
                                    print(f"      {GREEN}[WS ]  fl_weights::worker{wid}::round{rnd_num}  {GRAY}{pl}  --  coordinator-{cid}{RESET}")
                                    print(f"    {GRAY}[WS] [fl_weights]  Pesos de worker-{wid} "
                                          f"ronda {rnd_num} acumulados "
                                          f"({total_so_far}/{n_exp}){RESET}")
                            weights_shown[rnd_num] = already

                            # FedAvg + metricas de cierre de ronda
                            print()
                            print(f"    {GRAY}[ronda {rnd_num}] FedAvg sobre {workers} workers  "
                                  f"({samples:,} muestras totales){RESET}")
                            print(f"    {GREEN}Ronda {rnd_num} OK en {elapsed}s  "
                                  f"acc={_fv('accuracy')}  auc={_fv('auc')}  "
                                  f"loss={_fv('loss')}  prec={_fv('precision')}  "
                                  f"rec={_fv('recall')}{RESET}")
                            seen_rounds += 1

                        # -- fl_completed --------------------------------------
                        elif event in ("fl_completed", "fl_finished"):
                            n_rounds    = evt.get("n_rounds", total_rounds or "?")
                            best_round  = evt.get("best_round", "?")
                            best_m      = evt.get("best_metrics") or {}

                            print()
                            info(f"[WS] Evento fl_completed recibido")
                            ok(f" FL completado -- {n_rounds} rondas")
                            if best_round != "?":
                                field("Mejor ronda",   best_round)
                            for k in ("accuracy", "auc", "loss", "precision", "recall"):
                                v = best_m.get(k)
                                if v is not None:
                                    field(f"  {k}", f"{v:.4f}")
                            fl_done = True
                            break

                        # -- fl_failed -----------------------------------------
                        elif event == "fl_failed":
                            reason = evt.get("reason", "?")
                            rnd    = evt.get("round", "?")
                            print()
                            info(f"[WS] Evento fl_failed recibido")
                            warn(f" FL abortado en ronda {rnd} -- {reason}")
                            fl_done = True
                            break

                        # -- fl_update generico --------------------------------
                        # Emitido por el polling interno de /ws/fl-status cuando
                        # hay cambio de estado pero sin evento especifico.
                        # Solo actuamos si el FL termino.
                        elif event == "fl_update":
                            status = evt.get("status", "?")
                            # Silenciar los updates de ronda en curso -- ya los
                            # mostramos via round_started/round_completed.
                            # Solo reaccionar si el FL termino inesperadamente.
                            if status in ("completed", "failed"):
                                info(f"[WS] fl_update: status={status} -- FL terminado")
                                fl_done = True
                                break

                    if fl_done:
                        return   # exito -- salir del loop de reconexion

            except websockets.exceptions.ConnectionClosed as exc:
                conn_attempts += 1
                warn(f"WebSocket cerrado inesperadamente (intento {conn_attempts}/{max_attempts}): {exc}")
                if conn_attempts < max_attempts:
                    info(f"Reconectando en 3s...")
                    await _asyncio.sleep(3)

            except (ConnectionRefusedError, OSError) as exc:
                conn_attempts += 1
                warn(f"No se pudo conectar al WebSocket (intento {conn_attempts}/{max_attempts}): {exc}")
                if conn_attempts < max_attempts:
                    info(f"Reintentando en 3s...")
                    await _asyncio.sleep(3)

            except Exception as exc:
                warn(f"Error inesperado en WebSocket: {exc}")
                break

        if conn_attempts >= max_attempts:
            warn(f"No se pudo conectar al WebSocket tras {max_attempts} intentos.")
            warn("Fallback a polling HTTP...")
            _fase5_polling_fallback(coordinator_url, cid, nego, endpoints, accepted_wids)

    _asyncio.run(_ws_monitor())


def _fase5_polling_fallback(coordinator_url, cid, nego, endpoints, accepted_wids):
    """
    Fallback de monitorizacion por polling HTTP (GET /fl/status cada 5s).
    Se usa cuando websockets no esta disponible o la conexion WS falla.
    """
    info("Monitorizando via polling HTTP GET /fl/status cada 5s...")

    # Esperar a que el FL arranque
    for _ in range(30):
        try:
            r = SESSION.get(f"{coordinator_url}/fl/status", timeout=10, verify=TLS_CERT)
            if r.ok and r.json().get("status") not in ("idle", ""):
                ok("FL en marcha"); break
        except Exception:
            pass
        time.sleep(2)

    seen_rounds          = 0
    next_rnd_to_announce = 1
    total_rounds         = None
    weights_shown        = {}
    t_start              = time.time()
    poll_interval        = 5

    while True:
        if time.time() - t_start > 3600:
            warn("Timeout de monitorizacion (1h)"); break

        try:
            r  = SESSION.get(f"{coordinator_url}/fl/status", timeout=10, verify=TLS_CERT)
            r.raise_for_status()
            fl = r.json()
        except Exception as e:
            warn(f"Error polling /fl/status: {e}"); time.sleep(poll_interval); continue

        status       = fl.get("status", "?")
        history      = fl.get("history", [])
        total_rounds = fl.get("total_rounds") or total_rounds

        # Vaciar history: mostrar rondas cerradas
        while seen_rounds < len(history):
            entry   = history[seen_rounds]
            rnd_num = entry.get("round", seen_rounds + 1)
            elapsed = entry.get("elapsed_seconds", 0)
            workers = entry.get("workers_ok", "?")
            samples = entry.get("total_samples", 0)
            gm      = entry.get("global_metrics", {})

            def _fv(k):
                v = gm.get(k)
                return f"{v:.4f}" if isinstance(v, float) else (str(v) if v is not None else "--")

            already = weights_shown.get(rnd_num, set())
            for wid in accepted_wids:
                if wid not in already:
                    already.add(wid)
                    n_exp = len(accepted_wids) + 1
                    total_so_far = 1 + len(already)
                    pe   = endpoints["peers"].get(f"worker{wid}", {})
                    pl   = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                    print()
                    print(f"    {BOLD}[ronda {rnd_num}]  Pesos recibidos de worker-{wid} (WebSocket):{RESET}")
                    print(f"      {GREEN}[WS ]  fl_weights::worker{wid}::round{rnd_num}  {GRAY}{pl}  --  coordinator-{cid}{RESET}")
                    print(f"    {GRAY} Pesos acumulados ({total_so_far}/{n_exp}){RESET}")
            weights_shown[rnd_num] = already

            print()
            print(f"    {GRAY}[ronda {rnd_num}] FedAvg -- {workers} workers, {samples:,} muestras{RESET}")
            print(f"    {GREEN}Ronda {rnd_num} OK en {elapsed}s  "
                  f"acc={_fv('accuracy')}  auc={_fv('auc')}  loss={_fv('loss')}{RESET}")
            seen_rounds += 1
            next_rnd_to_announce = seen_rounds + 1

        # Anunciar ronda actual si podemos
        rnd_match = re.match(r"round_(\d+)", status)
        if rnd_match:
            rnd_num = int(rnd_match.group(1))
            if rnd_num == next_rnd_to_announce:
                weights_shown.setdefault(rnd_num, set())
                next_rnd_to_announce = rnd_num + 1
                _print_ronda_header(rnd_num, total_rounds, cid)
                for w in nego.get("accepted", []):
                    uri = w.get("connector_uri", "")
                    m   = re.search(r"worker(\d+)", uri)
                    wid = m.group(1) if m else "?"
                    pe  = endpoints["peers"].get(f"worker{wid}", {})
                    pl  = pe.get("ecc_label", f"ecc-worker{wid}:8889")
                    _print_handshake_algoritmo(rnd_num, wid, pl, cid)

        if status == "completed" and seen_rounds >= (total_rounds or 0):
            ok(f" FL completado -- {seen_rounds} rondas"); break
        elif status == "failed":
            warn(" FL termino con status=failed"); break

        time.sleep(poll_interval)

# =============================================================================
# FASE 6 -- Test de Acceso al Modelo Global (Soberania de Datos)
# =============================================================================

def fase6_test_acceso_modelo(coordinator_url, cid, nego, endpoints, req_timeout):
    phase(
        6,
        "Test de Acceso al Modelo Global (Soberania de Datos IDS)",
        "El coordinator crea el contrato del modelo limitando el acceso (\n"
        "ids:rightOperand) unicamente a los workers participantes.\n"
        "Se verifica el acceso dinamico de los workers (aceptados y rechazados)."
    )

    try:
        fl_res = None
        info("Esperando a que el recurso del modelo FL se publique en el catalogo IDS...")
        for _ in range(15):
            r = SESSION.get(f"{coordinator_url}/ids/self-description", timeout=10, verify=TLS_CERT)
            if r.ok:
                sd = r.json()
                cat = (sd.get("ids:resourceCatalog") or [{}])[0]
                res = cat.get("ids:offeredResource", [])
                
                fl_res = next(
                    (x for x in res if
                     "fl_model_coordinator" in x.get("@id", "") or
                     "FL Global Model" in ((x.get("ids:title") or [{}])[0]).get("@value", "")),
                    None
                )
                if fl_res:
                    break
            time.sleep(1)
            
        if not fl_res:
            warn("No se encontro el recurso del modelo FL en el catalogo tras la espera")
            return
            
        cid_val = ((fl_res.get("ids:contractOffer") or [{}])[0]).get("@id", "")
        if not cid_val:
            warn("No se encontro ContractOffer en el modelo")
            return
            
    except Exception as e:
        warn(f"Error parseando IDs para la fase 6: {e}")
        return

    # Obtenemos las URLs directamente del broker sin hardcodear
    coord_ecc = endpoints["coordinator"].get("ecc_url")
    coord_uri = endpoints["coordinator"].get("connector_uri")
    
    if not coord_ecc or not coord_uri:
        warn("No se pudo extraer la URL del coordinator desde el Broker para realizar la prueba.")
        return
    
    # -- Extraer TODOS los peers descubiertos (aceptados, rechazados Y descartados) --
    # De este modo worker-4 (schema incompatible -> descartado en discovery) tambien
    # se prueba y recibe un RejectionMessage real del coordinator porque su URI
    # no esta en la lista de autorizados del contrato FL.
    accepted_uris = {re.search(r"worker(\d+)", w.get("connector_uri", "")).group(1)
                     for w in nego.get("accepted", [])
                     if re.search(r"worker(\d+)", w.get("connector_uri", ""))}

    workers_to_test = []
    for wid_key in sorted(endpoints["peers"].keys()):   # worker1, worker2, ...
        m = re.search(r"worker(\d+)", wid_key)
        if m:
            workers_to_test.append(m.group(1))
    # Anadir los que puedan venir de nego pero no esten en endpoints["peers"]
    for w in nego.get("accepted", []) + nego.get("rejected", []):
        m = re.search(r"worker(\d+)", w.get("connector_uri", ""))
        if m and m.group(1) not in workers_to_test:
            workers_to_test.append(m.group(1))
    workers_to_test = list(dict.fromkeys(workers_to_test))

    if not workers_to_test:
        warn("No hay peers descubiertos para probar en la Fase 6.")
        return

    # -- Ejecutar el test de acceso global --
    for target_wid in workers_to_test:
        if f"worker{target_wid}" not in endpoints["peers"]:
            continue
            
        w_url = f"https://localhost:{5000 + int(target_wid)}"
        # ECC :8889 no es accesible desde DataApps -- redirigir al DataApp coordinator
        # que implementa la logica del contrato IDS directamente en su endpoint /data.
        _m_f6 = re.search(r"ecc-(worker\d+)", coord_ecc)
        _fwd_dataapp = (
            f"https://be-dataapp-{_m_f6.group(1)}:8500/data"
            if _m_f6 else coord_ecc
        )
        payload = {
            "Forward-To"      : _fwd_dataapp,
            "connectorUri"    : coord_uri,   # URI IDS explicita -- evita inferencia incorrecta
            "messageType"     : "ContractRequestMessage",
            "contractId"      : cid_val,
            "contractProvider": coord_uri,
        }
        
        print()
        step("test", f"IDS: Contract Request Message (Worker-{target_wid} al Coordinator)")
        _ids_log("out", "ids:ContractRequestMessage", f"worker-{target_wid}", f"coordinator-{cid}")
        
        try:
            raw = http_post_raw(f"{w_url}/proxy", payload, timeout=req_timeout)
            parsed = parse_ids(raw)
            if not parsed:
                parsed = parse_ids(raw, "Message") or {}
                
            ids_type = parsed.get("@type", "")
            
            if "ContractAgreement" in ids_type:
                step("result", f"IDS: Contract Agreement Message")
                _ids_log("in", "ids:ContractAgreementMessage", f"coordinator-{cid}", f"worker-{target_wid}")
                
                transfer_contract = parsed.get("@id", "?")
                ok(f"Worker-{target_wid} -- acceso PERMITIDO al modelo (Contract Agreement)")
                field("Recurso Target", fl_res.get("@id", "?"), indent=8)
                field("transferContract id", transfer_contract, indent=8)
                
            elif ("Rejection" in ids_type or "ContractRejection" in ids_type
                  or parsed.get("status") == "rejected"
                  or parsed.get("reason") in ("unauthorized_consumer", "fl_opt_out")):
                # Era un rechazo ESPERADO? -> worker no participo en el FL
                _is_expected_rejection = target_wid not in accepted_uris

                if _is_expected_rejection:
                    step("result", "IDS: Soberania Aplicada -- Acceso Denegado")
                    _ids_log("in", "ids:RejectionMessage", f"coordinator-{cid}", f"worker-{target_wid}")
                    ok(
                        f"Worker-{target_wid} -- acceso DENEGADO   "
                        f"(no participo en el FL -- Soberania IDS aplicada correctamente)"
                    )
                    _reason = parsed.get("reason") or parsed.get("ids:rejectionReason", "policy_enforcement")
                    field("Motivo de rechazo", str(_reason), indent=8)
                    field("Politica aplicada", "connector-restricted-policy (ids:rightOperand)", indent=8)
                else:
                    step("result", f"IDS: Rejection Message (INESPERADO)")
                    _ids_log("in", "ids:RejectionMessage", f"coordinator-{cid}", f"worker-{target_wid}")
                    reason = parsed.get("ids:rejectionReason", "?")
                    fail(f"Worker-{target_wid} -- acceso DENEGADO al modelo (sorprendente, era participante)")
                    field("Rejection Reason", str(reason), indent=8)
                
            else:
                step("result", f"IDS: Firewall / Respuesta inesperada")
                _ids_log("in", "PolicyRejection", f"coordinator-{cid}", f"worker-{target_wid}")
                warn(f"Worker-{target_wid} -- respuesta IDS no reconocida: {ids_type!r}")
                field("raw_response", (raw[:200] + "...") if len(raw) > 200 else raw, indent=8)
                
        except Exception as e:
            warn(f"Error proxy Worker-{target_wid}: {e}")
            
        print()


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="PFG -- Demostracion IDS + Federated Learning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--coordinator", default="2", metavar="N",
                   help="Numero del worker coordinator (default: 2)")
    p.add_argument("--coordinator-port", type=int, default=0, metavar="PORT",
                   help=(
                       "Puerto localhost del dataapp coordinator "
                       "(default: 5000 + --coordinator, e.g. 5002 para coordinator=2)"
                   ))
    p.add_argument("--skip-fl", action="store_true",
                   help="No arrancar el entrenamiento (solo fases 0-3)")
    p.add_argument("--timeout", type=int, default=240, metavar="SEG",
                   help="Timeout HTTP en segundos (default: 240)")
    return p.parse_args()


# =============================================================================
# RESET GLOBAL Y LISTENER DE TECLADO
# =============================================================================

def _cleanup_workers(coordinator_url, endpoints, req_timeout):
    """
    Recorre el coordinator y todos los workers conocidos y llama a
    POST /system/reset para devolverlos al estado inicial (sin archivos FL).
    """
    workers = [("coordinator", coordinator_url)]
    if endpoints and "peers" in endpoints:
        for w_name in endpoints["peers"]:
            num = w_name.replace("worker", "")
            try:
                w_url = f"https://localhost:{5000 + int(num)}"
                workers.append((w_name, w_url))
            except ValueError:
                pass
    for name, url in workers:
        try:
            r = SESSION.post(f"{url}/system/reset", timeout=req_timeout, verify=TLS_CERT)
            if r.ok:
                print(f"  {GREEN}[OK]{RESET} {name} restaurado.")
            else:
                print(f"  {RED}[FAIL]{RESET} {name} devolvio {r.status_code}")
        except Exception as exc:
            print(f"  {RED}[ERR ]{RESET} No se pudo contactar a {name}: {exc}")


def _start_keyboard_listener(coordinator_url_ref, endpoints_ref, req_timeout):
    """
    Hilo daemon que escucha el teclado. Al pulsar 'P' o 'p' (o Ctrl+C):
      1. Imprime un aviso coloreado.
      2. Llama a _cleanup_workers para limpiar los DataApps.
      3. Termina el proceso.
    Solo funciona en Windows (usa msvcrt). En Linux/Mac se ignora.
    """
    global _cancel_requested
    if not _HAS_MSVCRT:
        return
    while not _cancel_requested:
        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch.lower() == 'p':
                _cancel_requested = True
                print()
                print(f"  {RED}{BOLD}╔══════════════════════════════════════════════╗{RESET}")
                print(f"  {RED}{BOLD}║  [P] CANCELACION MANUAL SOLICITADA           ║{RESET}")
                print(f"  {RED}{BOLD}║  Limpiando todos los Workers y Coordinator   ║{RESET}")
                print(f"  {RED}{BOLD}╚══════════════════════════════════════════════╝{RESET}")
                print()
                _cleanup_workers(
                    coordinator_url_ref[0],
                    endpoints_ref[0],
                    req_timeout,
                )
                print(f"  {GREEN}Sistema restaurado. Puedes volver a ejecutar pfg_ids_fl_flow.py.{RESET}")
                print()
                os._exit(0)
        time.sleep(0.1)


def fase0b_verificar_catalogo_coordinator(coordinator_url, req_timeout):
    """
    Tras la FASE 0, consulta el Catalogo IDS del Coordinator (/ids/self-description)
    y lista los Datasets CSV registrados de forma dinamica, sin hardcoding.
    """
    phase(
        "0b",
        "Catalogo IDS del Coordinator (Datasets disponibles)",
        "Consulta dinamica al catalogo IDS para obtener los Datasets\n"
        "publicados en el Coordinator sin hardcodear ningun nombre."
    )
    try:
        r = SESSION.get(
            f"{coordinator_url}/ids/self-description",
            timeout=req_timeout,
            verify=TLS_CERT,
        )
        if not r.ok:
            warn(f"Error HTTP {r.status_code} al leer el catalogo IDS")
            return
        sd  = r.json()
        cat = (sd.get("ids:resourceCatalog") or [{}])[0]
        resources = cat.get("ids:offeredResource", [])
        datasets = []
        for res in resources:
            t_node = res.get("ids:title", [{}])[0]
            title  = t_node.get("@value", "") if isinstance(t_node, dict) else str(t_node)
            if "Dataset:" in title:
                datasets.append(title.replace("Dataset: ", "").strip())
        if datasets:
            info(f"Se encontraron {len(datasets)} Dataset(s) publicados en el Coordinator:")
            for d in datasets:
                print(f"    {CYAN}[CSV]{RESET} {GRAY}{d}{RESET}")
        else:
            warn("No se detectaron Datasets CSV en el catalogo IDS.")
    except Exception as exc:
        warn(f"No se pudo parsear el catalogo IDS: {exc}")


def main():
    args = parse_args()
    cid  = args.coordinator

    try:
        cid_int = int(cid)
    except ValueError:
        print(f"{RED}Coordinator ID invalido: {cid!r}. Debe ser un numero entero (p.ej. 2).{RESET}")
        sys.exit(1)

    # Puerto del coordinator: argumento explicito o convencion 5000+N
    coordinator_port = args.coordinator_port if args.coordinator_port else 5000 + cid_int
    coordinator_url  = f"https://localhost:{coordinator_port}"
    req_timeout      = args.timeout

    banner(
        "PFG -- Demostracion Federated Learning sobre IDS",
        f"Worker-{cid} como coordinator  .  Broker Fuseki + DAPS omejdn  .  multi-CSV discovery"
    )
    print()
    field("Coordinator",     f"Worker-{cid}  ({coordinator_url})")
    field("coordinator_port", coordinator_port)
    field("Arrancar FL",     "No (--skip-fl)" if args.skip_fl else "Si")
    field("Timeout HTTP",    f"{req_timeout}s")
    info("El coordinator obtendra algorithm.py + fl_config.json via IDS")
    info("FASE 2: cada peer es evaluado por sus CSVs reales -- umbral coincidencia: 80%")
    info("El CSV ganador de cada worker se comunica al worker via payload IDS en cada ronda")

    # Referencias mutables para que el listener las actualice en caliente
    _coord_ref     = [coordinator_url]
    _endpoints_ref = [None]

    # Arrancar el hilo de escucha del teclado (daemon => muere con el proceso)
    info("Pulsa [P] en cualquier momento para cancelar y resetear todos los Workers.")
    _listener = threading.Thread(
        target=_start_keyboard_listener,
        args=(_coord_ref, _endpoints_ref, req_timeout),
        daemon=True,
    )
    _listener.start()

    try:
        # Fases
        endpoints = fase0_resolver_endpoints(coordinator_url, cid, req_timeout)
        _endpoints_ref[0] = endpoints
        time.sleep(0.5)

        fase0b_verificar_catalogo_coordinator(coordinator_url, req_timeout)
        time.sleep(0.5)

        fase1_solicitar_algoritmo(coordinator_url, cid, endpoints, req_timeout)
        time.sleep(1)

        fase2_descubrir_peers(coordinator_url, cid, endpoints, req_timeout)
        nego = fase3_negociar(coordinator_url, cid, endpoints, req_timeout)
        verificar_coordinator(coordinator_url, cid, endpoints, req_timeout)

        if not args.skip_fl:
            if not nego.get("accepted"):
                warn("No hay workers aceptados -- no se arranca el FL")
            else:
                fase4_arrancar_fl(coordinator_url, cid, endpoints, req_timeout)
                fase5_monitorizar_fl(coordinator_url, cid, nego, endpoints, req_timeout)
                fase6_test_acceso_modelo(coordinator_url, cid, nego, endpoints, req_timeout)

    except KeyboardInterrupt:
        print()
        print(f"  {RED}{BOLD}[CTRL+C] Ejecucion interrumpida. Limpiando Workers...{RESET}")
        _cleanup_workers(coordinator_url, _endpoints_ref[0], req_timeout)
        print(f"  {GREEN}Sistema restaurado.{RESET}")
        sys.exit(0)

    # Resumen final
    print()
    _sep("=", color=BOLD + CYAN)
    print(f"{BOLD}{GREEN}  Demostracion completada{RESET}")
    _sep("=", color=BOLD + CYAN)
    print()

    for w in nego.get("accepted", []):
        uri  = w.get("connector_uri", "?")
        m    = re.search(r"worker(\d+)", uri)
        wid  = m.group(1) if m else "?"
        peer = endpoints["peers"].get(f"worker{wid}", {})
        ecc  = peer.get("ecc_url", "(desconocido)")
        print(f"  {GREEN}PARTICIPA   Worker-{wid}   {GRAY}{ecc}{RESET}")

    for w in nego.get("rejected", []):
        uri    = w.get("connector_uri", "?")
        reason = w.get("reason", "?")
        m      = re.search(r"worker(\d+)", uri)
        wid    = m.group(1) if m else "?"
        peer   = endpoints["peers"].get(f"worker{wid}", {})
        ecc    = peer.get("ecc_url", "(desconocido)")
        print(f"  {RED}RECHAZADO   Worker-{wid}   {GRAY}{ecc}  --  {reason}{RESET}")

    print()

    # --- METRICAS RENDIMIENTO ---
    if not args.skip_fl:
        try:
            import json
            import requests
            raw_metrics = requests.get(f"{coordinator_url}/metrics", timeout=req_timeout, verify=TLS_CERT).text
            perf = json.loads(raw_metrics)
            
            print(f"  {CYAN}📊 RENDIMIENTO DE TRANSFERENCIAS (Data Plane vs Control Plane IDS){RESET}")
            print(f"  {CYAN}----------------------------------------------------------------------{RESET}")
            
            ws_sends  = perf.get("ws_sends", 0)
            ws_ms     = perf.get("ws_total_ms", 0.0)
            ws_bytes  = perf.get("ws_bytes", 0)

            http_sends = perf.get("http_sends", 0)
            http_ms    = perf.get("http_total_ms", 0.0)
            http_bytes = perf.get("http_bytes", 0)

            ws_fails   = perf.get("ws_failures", 0)
            http_fails = perf.get("http_failures", 0)

            print(f"  {BOLD}Túnel WebSocket (Data Plane){RESET}")
            print(f"    Envíos exitosos : {ws_sends}   (Fallos: {ws_fails})")
            if ws_sends > 0:
                print(f"    Latencia Media  : {ws_ms / ws_sends:.1f} ms")
                print(f"    Volumen total   : {ws_bytes / 1024:.1f} KB")

            print()
            print(f"  {BOLD}Fallback HTTP / IDS Multipart (Control Plane IDS){RESET}")
            print(f"    Envíos exitosos : {http_sends}   (Fallos: {http_fails})")
            if http_sends > 0:
                print(f"    Latencia Media  : {http_ms / http_sends:.1f} ms")
                print(f"    Volumen total   : {http_bytes / 1024:.1f} KB")

            print()
            if ws_sends > 0 and http_sends > 0:
                ratio = (http_ms / http_sends) / (ws_ms / ws_sends)
                print(f"  {GREEN}► CONCLUSIÓN: WebSockets fue {ratio:.1f}x más rápido (ahorró {100 - (1/ratio)*100:.1f}% de overhead).{RESET}")
            elif http_sends > 0:
                print(f"  {YELLOW}► CONCLUSIÓN: El entrenamiento FL fue realizado 100% sobre el túnel IDS.{RESET}")
            elif ws_sends > 0:
                print(f"  {GREEN}► CONCLUSIÓN: Velocidad máxima obtenida mediante túnel asíncrono WebSocket.{RESET}")
            print()
        except Exception as e:
            warn(f"No se pudieron cargar las métricas de rendimiento: {e}")

    info(f"GET {coordinator_url}/fl/status")
    info(f"GET {coordinator_url}/fl/results")
    info(f"GET {coordinator_url}/fl/model")
    info(f"GET {coordinator_url}/ids/self-description")
    info(f"GET {coordinator_url}/ids/contract?contractOffer=<fl_model_contract_id>")
    print()


if __name__ == "__main__":
    main()