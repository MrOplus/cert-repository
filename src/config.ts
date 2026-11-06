import 'dotenv/config';
import path from 'node:path';

function required(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`[config] Missing required env var ${name}. Run "npm run setup" to generate a .env file.`);
    process.exit(1);
  }
  return v;
}

function int(name: string, def: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    console.error(`[config] ${name} must be a positive number`);
    process.exit(1);
  }
  return n;
}

const masterKeyRaw = required('MASTER_KEY');
const masterKey = Buffer.from(masterKeyRaw, 'base64');
if (masterKey.length !== 32) {
  console.error('[config] MASTER_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32)');
  process.exit(1);
}

const adminToken = required('ADMIN_TOKEN');
if (adminToken.length < 32) {
  console.error('[config] ADMIN_TOKEN must be at least 32 characters');
  process.exit(1);
}

function trustProxy(): boolean | number | string {
  const v = process.env.TRUST_PROXY;
  if (!v || v === 'false') return false;
  if (v === 'true') return true;
  if (/^\d+$/.test(v)) return Number(v);
  return v; // e.g. "loopback" or a comma-separated list of subnets
}

export const config = {
  host: process.env.HOST || '127.0.0.1',
  port: int('PORT', 8443),
  dataDir: path.resolve(process.env.DATA_DIR || './data'),
  masterKey,
  adminToken,
  /** Serve the app itself over HTTPS using a certificate it manages for this domain. */
  tlsDomain: process.env.TLS_DOMAIN?.trim().toLowerCase() || undefined,
  trustProxy: trustProxy(),
  /** Hours between renewal checks. */
  checkIntervalHours: int('CHECK_INTERVAL_HOURS', 6),
  /** Optional bootstrap values, imported into the encrypted store on first start. */
  bootstrap: {
    cloudflareToken: process.env.CLOUDFLARE_API_TOKEN || undefined,
  },
};
