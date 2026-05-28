# Dynamic Attribute Provisioning Service (DAPS)

The **DAPS** is the identity provider and trust anchor of the International Data Spaces (IDS) ecosystem. It is responsible for verifying the identity of connectors and issuing cryptographically signed **Dynamic Attribute Tokens (DAT)** (OAuth 2.0 JSON Web Tokens).

---

## Role in IDS

Without a valid DAT issued by the DAPS, connectors cannot communicate with each other. The DAT contains security assertions about the connector (e.g., certification level, operator identity, integrity state).

1. **Authentication request**: Connector contacts DAPS, authenticating via its private key and X.509 certificate.
2. **DAT Issuance**: DAPS validates the certificate and issues a signed DAT (JWT).
3. **Message exchange**: When Connector A contacts Connector B, it embeds the DAT in the IDS message header.
4. **Verification**: Connector B decrypts/verifies the DAT using the DAPS public key to confirm A's authenticity and security profile.

---

## Structure

* `config/`: Contains Omejdn configurations, client definitions, and custom claims mappings.
  * `clients.yml`: Registers authorized clients (Worker 1-4, Broker, Clearing House, etc.), mapping their certificate subjects to Client IDs.
  * `scope_mapping.yml`: Maps request scopes to token claims.
* `keys/`: Cryptographic credentials.
  * `daps.key` / `daps.pub`: RS256 private and public keys used by Omejdn to sign and verify tokens.
  * Certs: Trusted certificate authority (CA) certificates for client verification.
* [nginx.conf](nginx.conf): Configures the Nginx reverse proxy. Handles TLS termination, certificate verification, and forwards traffic to the internal Omejdn service.

---

## Nginx Configuration Highlights

The DAPS endpoint is exposed securely on host port `8081` (redirecting to Omejdn on port `80`). Key configurations in [nginx.conf](nginx.conf):
* **SSL/TLS**: Uses standard modern TLS protocols (`TLSv1.2` and `TLSv1.3`).
* **Header Forwarding**: Preserves request hosts and protocols to ensure redirect URIs and token issuer fields are correctly formatted as public URLs.
* **Token Issuer Mapping**: Matches the DAPS configuration, ensuring the JWT payload contains the correct issuer URI (`https://daps/token`).

---

## Token Verification Check

DAPS runs inside the main Docker Compose stack. To verify token generation and client credentials:

1. Request a token using the Client Credentials Flow:
   ```bash
   curl -X POST https://localhost:8081/token \
     -d "grant_type=client_credentials" \
     -d "client_id=<worker_client_id>" \
     -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
     -d "client_assertion=<jwt_signed_with_worker_private_key>"
   ```
2. Inspect the returned JWT payload (e.g. via jwt.io) with the public key located at `DAPS/keys/daps.pub`.
