// Container health check: hits /healthz over HTTP, or HTTPS when TLS_DOMAIN is set.
import http from 'node:http';
import https from 'node:https';

const port = Number(process.env.PORT || 8443);
const domain = process.env.TLS_DOMAIN;
const mod = domain ? https : http;
const req = mod.get(
  {
    host: '127.0.0.1',
    port,
    path: '/healthz',
    timeout: 4000,
    ...(domain ? { servername: domain, rejectUnauthorized: false } : {}),
  },
  (res) => process.exit(res.statusCode === 200 ? 0 : 1),
);
req.on('timeout', () => req.destroy(new Error('timeout')));
req.on('error', () => process.exit(1));
