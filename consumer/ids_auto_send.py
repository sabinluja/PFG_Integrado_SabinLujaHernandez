"""
ids_auto_send.py — Envío automático de algorithm.py al Provider vía IDS
=======================================================================
Corre UNA sola vez al arrancar el contenedor be-dataapp-consumer.

Espera a que ECC-Consumer y ECC-Provider estén listos, luego envía
algorithm.py vía IDS ArtifactRequestMessage y termina.

Variables de entorno (configuradas en docker-compose.yml):
  ALGORITHM_PATH       ruta al algorithm.py dentro del contenedor
  ECC_CONSUMER_URL     URL del ECC Consumer  (https://ecc-consumer:8449)  ← OJO: el ECC, no el Java DataApp
  FORWARD_TO           URL interna del ECC Provider para IDS
  PROVIDER_DATA_APP    URL del DataApp Provider Python (para verificación)
  CONSUMER_CONNECTOR   URI del conector Consumer
  PROVIDER_CONNECTOR   URI del conector Provider
  MAX_WAIT_SECONDS     segundos máximos esperando a que arranquen los ECCs
  RETRY_INTERVAL       segundos entre reintentos
"""

import os
import sys
import json
import uuid
import time
import base64
import datetime
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuración desde entorno ───────────────────────────────────────────────
ALGORITHM_PATH     = os.getenv("ALGORITHM_PATH",     "/algorithm/algorithm.py")

# CORRECTO: apunta al ECC Consumer (:8449), no al Java DataApp (:8183)
ECC_CONSUMER_URL   = os.getenv("ECC_CONSUMER_URL",   "https://ecc-consumer:8449")

PROVIDER_DATA_APP  = os.getenv("PROVIDER_DATA_APP",  "http://be-dataapp-provider:8500")
CONSUMER_CONNECTOR = os.getenv("CONSUMER_CONNECTOR", "http://w3id.org/engrd/connector/consumer")
PROVIDER_CONNECTOR = os.getenv("PROVIDER_CONNECTOR", "http://w3id.org/engrd/connector/provider")
MAX_WAIT_SECONDS   = int(os.getenv("MAX_WAIT_SECONDS", "120"))
RETRY_INTERVAL     = int(os.getenv("RETRY_INTERVAL",  "5"))
ECC_USER           = os.getenv("ECC_USER",  "idsUser")
ECC_PASS           = os.getenv("ECC_PASS",  "passwordIdsUser")

# Forward-To: URL interna Docker del ECC Provider
FORWARD_TO = os.getenv("FORWARD_TO", "https://ecc-provider:8889/data")

# URLs directas a los Python FastAPI workers (red interna Docker)
WORKER_URLS = [
    os.getenv("WORKER_1_URL", "http://be-dataapp-provider:8500"),
    os.getenv("WORKER_2_URL", "http://ia-dataapp-2:8500"),
    os.getenv("WORKER_3_URL", "http://ia-dataapp-3:8500"),
]


def log(msg: str):
    ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}] [ids-sender] {msg}", flush=True)


def wait_for_service(url: str, name: str, timeout: int) -> bool:
    """Espera hasta que un servicio responda (cualquier código HTTP)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(url, verify=False, timeout=5)
            log(f"✅ {name} listo ({url})")
            return True
        except Exception:
            log(f"⏳ Esperando {name}...")
            time.sleep(RETRY_INTERVAL)
    log(f"❌ {name} no respondió en {timeout}s")
    return False


def send_algorithm_via_ids() -> bool:
    """
    Envía algorithm.py al Provider vía IDS usando el endpoint /proxy del ECC Consumer.

    El ECC Consumer (:8449/proxy) acepta un JSON con:
      - multipart        : "form"
      - Forward-To       : URL del ECC Provider
      - messageType      : tipo de mensaje IDS
      - requestedArtifact: URI del artefacto
      - payload          : contenido del fichero en base64

    Este es el mismo formato que usa Postman en el flujo IDS estándar.
    El ECC Consumer toma este JSON, construye el multipart IDS correcto
    y lo reenvía al ECC Provider.
    """
    if not os.path.exists(ALGORITHM_PATH):
        log(f"❌ algorithm.py no encontrado en {ALGORITHM_PATH}")
        return False

    with open(ALGORITHM_PATH, "rb") as f:
        algo_bytes = f.read()

    algo_b64 = base64.b64encode(algo_bytes).decode("utf-8")
    log(f"📄 algorithm.py leído: {len(algo_bytes)} bytes")

    # El endpoint /proxy es del ECC Consumer (puerto 8449), no del Java DataApp
    proxy_url = f"{ECC_CONSUMER_URL}/proxy"

    body = {
        "multipart"        : "form",
        "Forward-To"       : FORWARD_TO,
        "messageType"      : "ArtifactRequestMessage",
        "requestedArtifact": "http://w3id.org/engrd/connector/artifact/algorithm",
        "payload"          : algo_b64
    }

    log(f"📤 Enviando vía IDS:")
    log(f"   Proxy URL  : {proxy_url}")
    log(f"   Forward-To : {FORWARD_TO}")
    log(f"   messageType: ArtifactRequestMessage")

    try:
        resp = requests.post(
            proxy_url,
            json=body,
            auth=(ECC_USER, ECC_PASS),
            verify=False,
            timeout=60
        )
        log(f"📨 Respuesta HTTP: {resp.status_code}")
        log(f"   Body: {resp.text[:300]}")

        if resp.status_code == 200:
            log("✅ algorithm.py enviado correctamente vía IDS")
            return True
        else:
            log(f"❌ Error IDS: {resp.status_code} — {resp.text[:300]}")
            return False

    except Exception as e:
        log(f"❌ Error enviando vía IDS: {e}")
        return False


def push_algorithm_to_workers(algo_bytes: bytes) -> bool:
    """
    Entrega directa del algorithm.py a cada worker Python vía POST /upload-algorithm.

    Por qué es necesario:
      El ecc-provider enruta mensajes IDS al Java DataApp embebido
      (be-dataapp-provider:8183/data). Ese endpoint en el app.py Python
      maneja el mensaje y guarda el algoritmo. Pero como garantía adicional,
      también se hace push directo a los 3 workers.
    """
    log("📬 Push directo de algorithm.py a los 3 workers Python...")
    all_ok = True
    for i, base_url in enumerate(WORKER_URLS, start=1):
        url = f"{base_url}/upload-algorithm"
        try:
            resp = requests.post(
                url,
                files={"algorithm": ("algorithm.py", algo_bytes, "text/x-python")},
                timeout=30,
            )
            if resp.status_code == 200:
                log(f"   ✅ Worker {i} ({base_url}): OK")
            else:
                log(f"   ❌ Worker {i} ({base_url}): HTTP {resp.status_code}")
                all_ok = False
        except Exception as e:
            log(f"   ❌ Worker {i} ({base_url}): conexión fallida ({e})")
            all_ok = False
    return all_ok


def verify_workers(max_wait: int = 30, interval: int = 5) -> bool:
    """Verifica con retry que los 3 workers tienen algorithm.py cargado."""
    deadline = time.time() + max_wait
    attempt  = 0
    worker_names = ["be-dataapp-provider", "ia-dataapp-2", "ia-dataapp-3"]

    while time.time() < deadline:
        attempt += 1
        log(f"🔍 Verificando workers (intento {attempt})...")
        all_ok = True
        for i, name in enumerate(worker_names, start=1):
            try:
                resp = requests.get(f"http://{name}:8500/status", timeout=10)
                loaded = resp.json().get("algorithm_loaded", False)
                icon   = "✅" if loaded else "❌"
                log(f"   {icon} Worker {i} ({name}): algorithm_loaded={loaded}")
                if not loaded:
                    all_ok = False
            except Exception as e:
                log(f"   ⚠️  Worker {i} ({name}): no responde ({e})")
                all_ok = False

        if all_ok:
            log("✅ Todos los workers tienen algorithm.py")
            return True

        remaining = int(deadline - time.time())
        if remaining > 0:
            log(f"⏳ Reintentando en {interval}s ({remaining}s restantes)...")
            time.sleep(interval)

    log("⚠️  Algunos workers no confirmaron carga del algoritmo")
    return False


def main():
    log("=" * 55)
    log("  IDS Algorithm Auto-Sender arrancando")
    log("=" * 55)
    log(f"  Algorithm  : {ALGORITHM_PATH}")
    log(f"  ECC proxy  : {ECC_CONSUMER_URL}/proxy")
    log(f"  Forward-To : {FORWARD_TO}")
    log("=" * 55)

    # ── 1. Esperar servicios ───────────────────────────────────────────────────
    log("⏳ Esperando servicios...")
    ecc_ok      = wait_for_service(f"{ECC_CONSUMER_URL}/",        "ECC-Consumer",        MAX_WAIT_SECONDS)
    provider_ok = wait_for_service(f"{PROVIDER_DATA_APP}/health", "be-dataapp-provider", MAX_WAIT_SECONDS)

    if not ecc_ok:
        log("❌ ECC Consumer no disponible. Abortando envío IDS.")
        log("   El sistema sigue funcionando — copia algorithm.py manualmente")
        sys.exit(1)

    if not provider_ok:
        log("⚠️  be-dataapp-provider no responde aún, continuando...")

    # ── 2. Pausa adicional para ECC-Provider ───────────────────────────────────
    log("⏳ Pausa 10s para que ECC-Provider termine de inicializar...")
    time.sleep(10)

    # ── 3. Envío vía IDS ───────────────────────────────────────────────────────
    ids_ok = send_algorithm_via_ids()

    if not ids_ok:
        log("⚠️  Envío IDS falló. Reintentando en 15s...")
        time.sleep(15)
        ids_ok = send_algorithm_via_ids()

    # ── 4. Push directo a workers (garantía adicional) ─────────────────────────
    with open(ALGORITHM_PATH, "rb") as f:
        algo_bytes = f.read()

    time.sleep(3)
    push_ok = push_algorithm_to_workers(algo_bytes)

    if not push_ok:
        log("⚠️  Push directo parcial. Reintentando en 10s...")
        time.sleep(10)
        push_algorithm_to_workers(algo_bytes)

    # ── 5. Verificar ──────────────────────────────────────────────────────────
    time.sleep(3)
    all_ready = verify_workers(max_wait=30, interval=5)

    log("=" * 55)
    if ids_ok and all_ready:
        log("✅ Flujo IDS completado. Workers listos para FL.")
    elif all_ready:
        log("✅ Workers listos (push directo). Flujo IDS tuvo problemas.")
    else:
        log("⚠️  Completado con advertencias. Revisa los logs.")

    log("")
    log("  Para lanzar FL:")
    log("  curl -X POST http://localhost:8600/fl/start \\")
    log('       -H "Content-Type: application/json" \\')
    log('       -d \'{"rounds": 5}\'')
    log("=" * 55)
    sys.exit(0)


if __name__ == "__main__":
    main()