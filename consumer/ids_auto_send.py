"""
ids_auto_send.py — Envío automático de algorithm.py al Provider vía IDS
=======================================================================
Corre UNA sola vez al arrancar el contenedor ids-algorithm-sender.

Espera a que ECC-Consumer y ECC-Provider estén listos, luego envía
algorithm.py vía IDS ArtifactRequestMessage y termina.

Variables de entorno (configuradas en docker-compose.yml):
  ALGORITHM_PATH       ruta al algorithm.py dentro del contenedor
  ECC_CONSUMER_URL     URL del ECC Consumer  (https://ecc-consumer:8449)
  PROVIDER_ECC_URL     URL del ECC Provider  (https://ecc-provider:8449)
  PROVIDER_DATA_APP    URL del DataApp Provider (para verificación)
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

# El Java DataApp Consumer expone /proxy — igual que usa Postman
# Es distinto al /proxy del ECC (que requiere auth diferente)
PROXY_PATH = "/proxy"

# URLs directas a los Python FastAPI workers (red interna Docker)
# El ecc-provider llama al Java ECC (be-dataapp-provider:8183), que responde
# con datos del datalake local pero NO reenvía al Python :8500.
# La entrega real del algoritmo se hace directamente al Python.
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


def build_ids_header() -> str:
    """Construye el IDS ArtifactRequestMessage JSON-LD."""
    msg_id = str(uuid.uuid4())
    return json.dumps({
        "@context"             : "https://w3id.org/idsa/contexts/context.jsonld",
        "@type"                : "ids:ArtifactRequestMessage",
        "@id"                  : f"https://w3id.org/idsa/autogen/artifactRequestMessage/{msg_id}",
        "ids:modelVersion"     : "4.1.0",
        "ids:issued"           : {
            "@value": datetime.datetime.utcnow().isoformat() + "Z",
            "@type" : "xsd:dateTimeStamp"
        },
        "ids:issuerConnector"  : {"@id": CONSUMER_CONNECTOR},
        "ids:senderAgent"      : {"@id": CONSUMER_CONNECTOR},
        "ids:recipientConnector": [{"@id": PROVIDER_CONNECTOR}],
        "ids:requestedArtifact": {"@id": "https://w3id.org/idsa/autogen/artifact/algorithm.py"},
        "ids:contentVersion"   : "1.0",
        "ids:description"      : [{
            "@value": "Automatic FL algorithm deployment",
            "@language": "en"
        }]
    })


def send_algorithm() -> bool:
    """
    Envía algorithm.py al Provider vía IDS.

    El Java DataApp Consumer (/proxy) espera un JSON body con estos campos:
      - multipart        : tipo de multipart ("form")
      - Forward-To       : URL del ECC Provider
      - messageType      : tipo de mensaje IDS
      - requestedArtifact: URI del artefacto
      - payload          : contenido del fichero en base64

    Este es exactamente el mismo formato que usa Postman en el paso 5.
    """

    # 1. Leer fichero
    if not os.path.exists(ALGORITHM_PATH):
        log(f"❌ algorithm.py no encontrado en {ALGORITHM_PATH}")
        return False

    with open(ALGORITHM_PATH, "rb") as f:
        algo_bytes = f.read()

    # Codificar en base64 para incluirlo en el JSON
    algo_b64 = base64.b64encode(algo_bytes).decode("utf-8")
    log(f"📄 algorithm.py leído: {len(algo_bytes)} bytes")

    proxy_url = f"{ECC_CONSUMER_URL}/proxy"

    # 2. Body JSON — formato que espera el Java DataApp Consumer
    body = {
        "multipart"        : "form",
        "Forward-To"       : FORWARD_TO,
        "messageType"      : "ArtifactRequestMessage",
        "requestedArtifact": "http://w3id.org/engrd/connector/artifact/algorithm",
        "payload"          : algo_b64
    }

    log(f"📤 Enviando a {proxy_url}")
    log(f"   Forward-To: {FORWARD_TO}")
    log(f"   messageType: ArtifactRequestMessage")

    # 3. POST al Java DataApp Consumer
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
            log(f"✅ algorithm.py enviado correctamente vía IDS")
            return True
        else:
            log(f"❌ Error: {resp.status_code} — {resp.text[:300]}")
            return False

    except Exception as e:
        log(f"❌ Error enviando: {e}")
        return False

def push_algorithm_to_workers(algo_bytes: bytes) -> bool:
    """
    Entrega directa del algorithm.py a cada worker Python vía POST /upload-algorithm.

    Por qué es necesario:
      El ecc-provider enruta mensajes IDS al Java DataApp embebido
      (be-dataapp-provider:8183), que responde con datos del datalake local
      (contrato demo). El Java DataApp NO reenvía el payload al Python
      FastAPI en :8500. Por tanto, el algoritmo debe entregarse directamente.

    Los workers 1, 2 y 3 comparten el volumen ia_algorithm montado en
    /app-src/. En cuanto worker 1 recibe el fichero, los otros lo ven via
    volumen compartido. Pero para garantía se envía a los 3.
    """
    log("📬 Distribuyendo algorithm.py directamente a los workers Python...")
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
                log(f"   ✅ Worker {i} ({base_url}): algorithm.py entregado")
            else:
                log(f"   ❌ Worker {i} ({base_url}): HTTP {resp.status_code} — {resp.text[:100]}")
                all_ok = False
        except Exception as e:
            log(f"   ❌ Worker {i} ({base_url}): error de conexión ({e})")
            all_ok = False
    return all_ok


def verify_workers() -> bool:
    """Verifica una vez que los 3 workers tienen algorithm.py."""
    log("🔍 Verificando workers...")
    all_ok = True
    # Los workers son accesibles internamente por nombre de contenedor
    worker_names = ["be-dataapp-provider", "ia-dataapp-2", "ia-dataapp-3"]
    for i, name in enumerate(worker_names, start=1):
        url = f"http://{name}:8500/status"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            loaded = data.get("algorithm_loaded", False)
            icon   = "✅" if loaded else "❌"
            log(f"   {icon} Worker {i} ({name}): algorithm_loaded={loaded}")
            if not loaded:
                all_ok = False
        except Exception as e:
            log(f"   ⚠️  Worker {i} ({name}): no responde ({e})")
            all_ok = False
    return all_ok


def verify_workers_with_retry(max_wait: int = 30, interval: int = 5) -> bool:
    """Reintenta la verificación de workers durante max_wait segundos.
    
    El flujo IDS completo (Consumer → ECC → Provider → distribuir a workers)
    puede tardar más de 3s. Con retry evitamos falsos negativos.
    """
    deadline = time.time() + max_wait
    attempt  = 0
    while time.time() < deadline:
        attempt += 1
        log(f"🔍 Verificando workers (intento {attempt})...")
        if verify_workers():
            log("✅ Todos los workers tienen algorithm.py cargado")
            return True
        remaining = int(deadline - time.time())
        if remaining > 0:
            log(f"⏳ Workers aún no listos, reintentando en {interval}s ({remaining}s restantes)...")
            time.sleep(interval)
    log("⚠️  Algunos workers no confirmaron carga del algoritmo tras el tiempo de espera")
    return False


def main():
    log("=" * 50)
    log("  IDS Algorithm Auto-Sender arrancando")
    log("=" * 50)
    log(f"  Algorithm : {ALGORITHM_PATH}")
    log(f"  ECC       : {ECC_CONSUMER_URL}")
    log(f"  Forward-To: {FORWARD_TO}")
    log("=" * 50)

    # 1. Esperar a que arranquen los servicios necesarios
    # Esperamos al ECC Consumer y al DataApp Provider (worker 1)
    log("⏳ Esperando a que los servicios estén listos...")

    ecc_ok      = wait_for_service(f"{ECC_CONSUMER_URL}/",          "ECC-Consumer",        MAX_WAIT_SECONDS)
    provider_ok = wait_for_service(f"{PROVIDER_DATA_APP}/health",   "be-dataapp-provider", MAX_WAIT_SECONDS)

    if not ecc_ok:
        log("❌ ECC Consumer no está disponible. Abortando.")
        sys.exit(1)

    if not provider_ok:
        log("⚠️  be-dataapp-provider no responde, intentando enviar igualmente...")

    # 2. Pequeña pausa adicional para que el ECC Provider también esté listo
    log("⏳ Pausa de 10s para que ECC-Provider termine de inicializar...")
    time.sleep(10)

    # 3. Enviar algorithm.py vía IDS
    success = send_algorithm()

    if not success:
        log("❌ Envío fallido. Reintentando una vez más en 15s...")
        time.sleep(15)
        success = send_algorithm()

    if not success:
        log("❌ No se pudo enviar algorithm.py. Revisa los logs de ecc-consumer y ecc-provider.")
        sys.exit(1)

    # 4. Entregar algorithm.py directamente a los workers Python
    #    (el Java DataApp embebido no reenvía el payload al Python FastAPI)
    with open(ALGORITHM_PATH, "rb") as f:
        algo_bytes = f.read()
    push_ok = push_algorithm_to_workers(algo_bytes)
    if not push_ok:
        log("⚠️  Algunos workers no recibieron el algoritmo directamente, reintentando en 10s...")
        time.sleep(10)
        push_algorithm_to_workers(algo_bytes)

    # 5. Verificar workers con retry (el flujo IDS puede tardar varios segundos)
    time.sleep(3)  # pausa mínima inicial
    verify_workers_with_retry(max_wait=30, interval=5)

    log("=" * 50)
    log("✅ ids-algorithm-sender completado. Contenedor terminando.")
    log("   Los workers tienen algorithm.py y están listos para FL.")
    log("   Lanza el FL con: curl -X POST http://localhost:8600/fl/start -d '{\"rounds\":5}'")
    log("=" * 50)
    sys.exit(0)


if __name__ == "__main__":
    main()