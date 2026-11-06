#!/usr/bin/env node
// Generates a .env file with strong random secrets. Refuses to overwrite an existing one.
import { existsSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

const printOnly = process.argv.includes('--print');

if (!printOnly && existsSync('.env')) {
  console.error('.env already exists — not overwriting. Delete it first if you really want new secrets\n(changing MASTER_KEY makes existing encrypted data unreadable).');
  process.exit(1);
}
const adminToken = randomBytes(32).toString('base64url');
const content = `# CertStore configuration — keep this file secret.
HOST=127.0.0.1
PORT=8443
DATA_DIR=./data

# 32-byte key that encrypts Cloudflare tokens and private keys at rest. BACK IT UP; losing it = losing the data.
MASTER_KEY=${randomBytes(32).toString('base64')}

# Bearer token for the admin panel / admin API.
ADMIN_TOKEN=${adminToken}

# Optional: serve CertStore itself over HTTPS with a certificate it manages (requires a Cloudflare token).
# TLS_DOMAIN=certs.example.com

# Optional: when behind a reverse proxy (nginx, Caddy, Cloudflare Tunnel) so client IPs are correct.
# TRUST_PROXY=loopback

# Optional first-start bootstrap (imported into the encrypted store, then can be removed):
# CLOUDFLARE_API_TOKEN=

# CHECK_INTERVAL_HOURS=6
`;

if (printOnly) {
  // For Docker: docker run --rm <image> node scripts/setup.mjs --print > .env
  process.stdout.write(content);
} else {
  writeFileSync('.env', content, { mode: 0o600 });
  console.log('Wrote .env (mode 600).\n\nAdmin token (also in .env):\n  ' + adminToken);
}
