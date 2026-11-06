# CertStore

Self-hosted SSL certificate store. It issues and **automatically renews** Let's Encrypt certificates using
Cloudflare DNS-01 challenges, and serves them to your other servers over an authenticated API.

- Multiple domains / certificates (SANs and wildcards supported)
- Multiple Cloudflare API tokens: each certificate picks which token to use
- Admin panel at `/` for certificates, tokens, API keys, settings and the audit log
- Per-server API keys, scoped to specific certificates, with optional IP/CIDR allow-list and expiry
- Secrets encrypted at rest (AES-256-GCM): Cloudflare tokens, ACME account keys, certificate private keys
- ACME account email defaults to `admin@<domain>` (e.g. `api.example.com` → `admin@example.com`), with a per-certificate override
- Audit log of every download, admin change, issuance and failed auth

## Quick start (Docker)

Images are published to GHCR for `linux/amd64` and `linux/arm64` by the GitHub workflow in `.github/workflows/docker.yml`.

```bash
mkdir certstore && cd certstore
curl -fsSLO https://raw.githubusercontent.com/mroplus/cert-repository/main/docker-compose.yml

# generate .env with a random MASTER_KEY and ADMIN_TOKEN
docker run --rm ghcr.io/mroplus/cert-repository:latest node scripts/setup.mjs --print > .env
chmod 600 .env
grep ADMIN_TOKEN .env   # this is your admin panel login

docker compose up -d     # http://127.0.0.1:8443
```

Data (the encrypted store) is kept in the `certstore-data` volume. Back up the volume **and** `.env`.
To build locally instead of pulling, run `docker compose up -d --build`.

The compose file publishes the port on `127.0.0.1` only. To expose CertStore publicly, choose one of these:
- put a TLS reverse proxy in front and set `TRUST_PROXY` in `.env`; or
- set `TLS_DOMAIN=certs.example.com` and `CLOUDFLARE_API_TOKEN=...` in `.env`, then change the port mapping to `"8443:8443"`. CertStore then serves HTTPS itself.

Image tags: `latest` (main branch), `X.Y.Z` / `X.Y` / `X` (git tags `vX.Y.Z`), and `sha-<short>`.

## Quick start (Node)

```bash
npm install
npm run setup        # writes .env with random MASTER_KEY + ADMIN_TOKEN (prints the admin token)
npm run build
npm start            # http://127.0.0.1:8443
```

Open the panel, sign in with `ADMIN_TOKEN`, then:

1. **Cloudflare tokens → Add token.** The token needs *Zone:DNS:Edit* and *Zone:Zone:Read*. It is verified against Cloudflare before saving.
2. **Certificates → New certificate.** Enter domains, pick the token, and choose production or staging.
3. **API keys → New API key.** Scope it to the certificates a server needs. The key is shown once.

Development: `npm run dev` (tsx watch).

## Download API

Authenticate with `Authorization: Bearer <key>` (or `X-API-Key: <key>`).

| Endpoint | Returns |
| --- | --- |
| `GET /api/v1/certs` | certificates this key can access (metadata only) |
| `GET /api/v1/certs/:domain` | JSON: `cert`, `chain`, `fullchain`, `privateKey`, `notAfter`, `fingerprint` |
| `GET /api/v1/certs/:domain/fullchain.pem` | leaf + intermediates |
| `GET /api/v1/certs/:domain/privkey.pem` | private key |
| `GET /api/v1/certs/:domain/cert.pem`, `chain.pem` | leaf / intermediates |
| `GET /api/v1/certs/:domain/bundle.pem` | key + fullchain (HAProxy) |

Responses carry `ETag: "<sha256 fingerprint>"`, so pollers can send `If-None-Match` and get `304` when nothing has changed.
If a certificate doesn't exist, or the key isn't allowed to see it, the response is `404` in both cases, so keys can't enumerate domains.

```bash
curl -fsS -H "Authorization: Bearer $KEY" https://certs.example.com/api/v1/certs/api.example.com/fullchain.pem -o fullchain.pem
```

### Auto-sync on client servers

`scripts/certstore-sync.sh` downloads the certificate and checks that the key matches it. It then
replaces the files atomically and runs your reload command, but only when the certificate has changed. Run it hourly from cron:

```cron
0 * * * * CERTSTORE_URL=https://certs.example.com CERTSTORE_KEY=cs_... DOMAIN=api.example.com DEST=/etc/ssl/api.example.com RELOAD_CMD="systemctl reload nginx" /usr/local/bin/certstore-sync.sh
```

## Renewal

A background check runs every `CHECK_INTERVAL_HOURS` (default 6) and once at startup. A certificate renews when fewer than
*N* days remain (Settings, default 30) or when a third of its lifetime remains, whichever comes first. If a renewal
fails, the previous certificate keeps being served and the job retries with exponential backoff (1h → 24h). The error
shows in the panel and the audit log. You can trigger **Renew now** manually at any time.

## Deployment & security notes

- **Always use HTTPS.** Choose one of these:
  - put CertStore behind nginx, Caddy or a Cloudflare Tunnel, and set `TRUST_PROXY=loopback` so client IPs are logged correctly; or
  - set `TLS_DOMAIN=certs.example.com`. CertStore then issues its own certificate before it starts listening and serves HTTPS directly, reloading the certificate on renewal. On first start this needs `CLOUDFLARE_API_TOKEN` in `.env`; the token is imported into the encrypted store, after which you can remove it from `.env`.
- `HOST` defaults to `127.0.0.1`. Set `HOST=0.0.0.0` only if you use `TLS_DOMAIN` or a proxy.
- **Back up `MASTER_KEY` and `data/`.** Without the key, the encrypted data can't be recovered.
- After 10 failed authentication attempts, an IP is locked out for 15 minutes.
- `data/store.json` is written atomically with mode `0600`.

## Configuration (`.env`)

| Var | Default | |
| --- | --- | --- |
| `MASTER_KEY` | required | 32 bytes, base64 |
| `ADMIN_TOKEN` | required | ≥ 32 chars |
| `HOST` / `PORT` | `127.0.0.1` / `8443` | |
| `DATA_DIR` | `./data` | |
| `TLS_DOMAIN` | – | serve HTTPS using a managed certificate |
| `TRUST_PROXY` | `false` | `true`, hop count, `loopback`, or a list of subnets |
| `CHECK_INTERVAL_HOURS` | `6` | |
| `CLOUDFLARE_API_TOKEN` | – | imported once on first start |
