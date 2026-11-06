import { Router, type Request, type Response } from 'express';
import type { Store, Certificate } from '../store.js';
import type { Vault } from '../crypto.js';
import { clientIp, keyCanAccess } from '../auth.js';

const FILES = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem', 'bundle.pem'] as const;
type FileName = (typeof FILES)[number];

/** Read-only certificate download API for other servers (API-key auth). */
export function clientRouter(store: Store, vault: Vault): Router {
  const r = Router();

  const lookup = (req: Request, res: Response): Certificate | undefined => {
    const id = String(req.params.id).toLowerCase();
    const cert = store.get().certificates.find((c) => c.id === id);
    // Same 404 for "doesn't exist" and "not allowed" so keys can't enumerate domains.
    if (!cert || !keyCanAccess(req.apiKey!, cert.id) || !cert.cert || !cert.privateKey) {
      res.status(404).json({ error: 'Certificate not found or not yet issued' });
      return undefined;
    }
    return cert;
  };

  const audit = (req: Request, target: string, detail: string) =>
    store.audit({ actor: `key:${req.apiKey!.name}`, action: 'cert.download', target, ip: clientIp(req), ok: true, detail });

  /** ETag = certificate fingerprint, so clients can poll cheaply with If-None-Match. */
  const notModified = (req: Request, res: Response, cert: Certificate): boolean => {
    const etag = `"${cert.fingerprint}"`;
    res.setHeader('ETag', etag);
    return req.get('if-none-match') === etag;
  };

  r.get('/certs', (req, res) => {
    const list = store
      .get()
      .certificates.filter((c) => keyCanAccess(req.apiKey!, c.id) && c.cert)
      .map((c) => ({
        id: c.id,
        domains: c.domains,
        fingerprint: c.fingerprint,
        notBefore: c.notBefore,
        notAfter: c.notAfter,
        acmeEnv: c.acmeEnv,
      }));
    res.json(list);
  });

  r.get('/certs/:id', async (req, res) => {
    const cert = lookup(req, res);
    if (!cert) return;
    if (notModified(req, res, cert)) return res.status(304).end();
    await audit(req, cert.id, 'json');
    res.json({
      id: cert.id,
      domains: cert.domains,
      fingerprint: cert.fingerprint,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      acmeEnv: cert.acmeEnv,
      cert: cert.cert,
      chain: cert.chain,
      fullchain: cert.cert! + cert.chain,
      privateKey: vault.decrypt(cert.privateKey!),
    });
  });

  r.get('/certs/:id/:file', async (req, res) => {
    const file = req.params.file as FileName;
    if (!FILES.includes(file)) return res.status(404).json({ error: `Unknown file. Use one of: ${FILES.join(', ')}` });
    const cert = lookup(req, res);
    if (!cert) return;
    if (notModified(req, res, cert)) return res.status(304).end();

    const key = () => vault.decrypt(cert.privateKey!);
    const body: Record<FileName, () => string> = {
      'cert.pem': () => cert.cert!,
      'chain.pem': () => cert.chain!,
      'fullchain.pem': () => cert.cert! + cert.chain,
      'privkey.pem': key,
      'bundle.pem': () => key() + cert.cert! + cert.chain, // HAProxy-style
    };
    await audit(req, cert.id, file);
    res.type('application/x-pem-file').send(body[file]());
  });

  return r;
}
