import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import { config } from './config.js';
import { Store } from './store.js';
import { Vault, randomId, secretHint } from './crypto.js';
import { Cloudflare } from './cloudflare.js';
import { CertManager } from './manager.js';
import { requireAdmin, requireApiKey } from './auth.js';
import { adminRouter, defaultEmail } from './routes/admin.js';
import { clientRouter } from './routes/client.js';

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');

async function bootstrap(store: Store, vault: Vault) {
  const { cloudflareToken } = config.bootstrap;
  if (cloudflareToken && store.get().credentials.length === 0) {
    const zones = await new Cloudflare(cloudflareToken).listZones();
    await store.update((d) => {
      d.credentials.push({
        id: randomId(),
        name: 'Default (from env)',
        token: vault.encrypt(cloudflareToken),
        hint: secretHint(cloudflareToken),
        zones,
        lastVerifiedAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      });
    });
    console.log('[bootstrap] Imported CLOUDFLARE_API_TOKEN into the encrypted store. You can now remove it from .env.');
  }
}

/** When TLS_DOMAIN is set, make sure we have a certificate for it before listening. */
async function ensureOwnCertificate(store: Store, manager: CertManager, domain: string) {
  let cert = store.get().certificates.find((c) => c.id === domain);
  if (!cert) {
    const cred = store.get().credentials[0];
    if (!cred) throw new Error(`TLS_DOMAIN=${domain} requires a Cloudflare credential (set CLOUDFLARE_API_TOKEN for first start)`);
    await store.update((d) => {
      d.certificates.push({
        id: domain,
        domains: [domain],
        credentialId: cred.id,
        email: defaultEmail(domain, cred.zones),
        acmeEnv: 'production',
        keyType: 'ecdsa',
        status: 'pending',
        failures: 0,
        createdAt: new Date().toISOString(),
      });
    });
    cert = store.get().certificates.find((c) => c.id === domain)!;
  }
  if (!cert.cert || new Date(cert.notAfter!).getTime() < Date.now()) {
    console.log(`[tls] Obtaining certificate for ${domain} before starting HTTPS…`);
    await manager.issue(domain, 'server certificate');
  }
}

function tlsMaterial(store: Store, vault: Vault, domain: string) {
  const c = store.get().certificates.find((x) => x.id === domain);
  if (!c?.cert || !c.privateKey) throw new Error(`No certificate for ${domain}`);
  return { cert: c.cert + (c.chain ?? ''), key: vault.decrypt(c.privateKey), notAfter: c.notAfter };
}

async function main() {
  const vault = new Vault(config.masterKey);
  const store = await Store.open(config.dataDir);
  await bootstrap(store, vault);
  const manager = new CertManager(store, vault, config.checkIntervalHours);

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.use(helmet({ hsts: config.tlsDomain ? undefined : false }));
  app.use(express.json({ limit: '64kb' }));
  app.use('/api', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true });
  });
  app.use('/api/admin', requireAdmin(store, config.adminToken), adminRouter(store, vault, manager));
  app.use('/api/v1', requireApiKey(store), clientRouter(store, vault));
  app.use(express.static(publicDir, { index: 'index.html' }));

  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });
  app.use((err: Error & { status?: number; type?: string }, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status ?? (err.type === 'entity.parse.failed' ? 400 : 500);
    if (status >= 500) console.error(err);
    res.status(status).json({ error: status >= 500 ? 'Internal server error' : err.message });
  });

  let server: http.Server | https.Server;
  if (config.tlsDomain) {
    const domain = config.tlsDomain;
    await ensureOwnCertificate(store, manager, domain);
    const { cert, key } = tlsMaterial(store, vault, domain);
    const s = https.createServer({ minVersion: 'TLSv1.2', cert, key }, app);
    manager.on('issued', (id: string) => {
      if (id !== domain) return;
      const m = tlsMaterial(store, vault, domain);
      s.setSecureContext({ cert: m.cert, key: m.key, minVersion: 'TLSv1.2' });
      console.log(`[tls] Reloaded certificate for ${domain} (expires ${m.notAfter})`);
    });
    server = s;
  } else {
    server = http.createServer(app);
    const loopback = ['127.0.0.1', '::1', 'localhost'].includes(config.host);
    if (!loopback && !config.trustProxy && !process.env.CERTSTORE_CONTAINER) {
      console.warn('[warn] Serving plain HTTP on a non-loopback interface. Put this behind a TLS reverse proxy or set TLS_DOMAIN.');
    }
  }

  manager.start();
  server.listen(config.port, config.host, () => {
    const proto = config.tlsDomain ? 'https' : 'http';
    console.log(`CertStore listening on ${proto}://${config.host}:${config.port}`);
  });

  const shutdown = () => {
    manager.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
