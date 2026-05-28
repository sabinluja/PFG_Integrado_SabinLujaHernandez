# Public Key Infrastructure & Certificates (certs)

This directory houses the cryptographical credentials, Java Keystores, and truststores required to secure communication within the IDS Testbed ecosystem.

---

## Certificate and Key Hierarchy

The IDS model enforces mutual authentication (mTLS) for all transactions and cryptographically signed tokens (DAT) for authorization.

```
                  ┌────────────────────────┐
                  │  Private Trust Anchor  │
                  │   (Root Cert Authority)│
                  └───────────┬────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ DAPS Credentials│  │ TLS Credentials │  │ Peer truststore │
│     (.p12)      │  │(ssl-server.jks) │  │(truststoreEcc)  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## File Description

### 1. DAPS Authentication (PKCS12 Keystores)
These are PKCS12 keystore files (`.p12`) used by the components to authenticate against the DAPS during OAuth2 Client Credentials grant to obtain a DAT token.
* `worker1-daps.p12` to `worker4-daps.p12`: Contains the private key, public certificate, and CA chain for Worker 1, 2, 3, and 4 ECCs.
* `clearinghouse-daps.p12`: Credentials for the Clearing House service to authenticate itself against DAPS.

### 2. TLS Keystores (Java Keystores - JKS)
* `ssl-server.jks`: Exposes the server-side TLS certificate used by the ECC instances to encrypt and authenticate incoming HTTPS traffic on host ports.
* `truststoreEcc.jks`: The Execution Core truststore. It contains the public certificates of the Root CA and intermediate CAs. The ECC checks this truststore to validate incoming client certificates during mTLS handshakes.

### 3. General Public Certificates
* `execution_core_container.cer`: Public certificate of the default Execution Core Container.
* `trueconn.pub`: Public key used by the TRUE Connector execution environment.
* `daps/` and `dataapp/`: Subdirectories with specific X.509 PEM certificates used for internal services TLS.

---

## Cryptographic Maintenance Tools

You can inspect or modify these keystores using the Java `keytool` CLI utility or `openssl`.

### Inspecting JKS Keystore Contents
To view certificates stored inside the truststore:
```bash
keytool -list -v -keystore truststoreEcc.jks -storepass password
```

### Inspecting PKCS12 Keystores (.p12)
To inspect the certificates and credentials within a worker's DAPS certificate:
```bash
openssl pkcs12 -info -in worker1-daps.p12 -passin pass:password
```

### Extracting a Public Certificate from PKCS12
If you need to extract the PEM certificate for DAPS registration:
```bash
openssl pkcs12 -in worker1-daps.p12 -clcerts -nokeys -out worker1.crt -passin pass:password
```
