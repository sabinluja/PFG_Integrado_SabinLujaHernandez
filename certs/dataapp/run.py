import ssl, asyncio, sys
sys.path.insert(0, "/app")
import uvicorn
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_ctx.load_cert_chain("/cert/dataapp/cert.pem", "/cert/dataapp/key.pem")
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_ctx.set_ciphers(
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-CHACHA20-POLY1305"
)
config = uvicorn.Config("app:app", host="0.0.0.0", port=8500, log_level="info")
config.load()
config.ssl = ssl_ctx
asyncio.run(uvicorn.Server(config).serve())
