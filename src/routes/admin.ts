import { Router, type Request } from 'express';
import type { Store, Certificate, AcmeEnv, KeyType, CloudflareCredential, ApiKey } from '../store.js';
import { Vault, randomId, randomToken, hashToken, secretHint } from '../crypto.js';
import { Cloudflare } from '../cloudflare.js';
import type { CertManager } from '../manager.js';
import { clientIp, validateIpRule } from '../auth.js';

const HOSTNAME_RE = /^(\*\.)?(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** admin@<zone apex>, e.g. api.example.com -> admin@example.com */
export function defaultEmail(domain: string, zones: string[]): string {
  const host = domain.replace(/^\*\./, '');
  const zone = zones
    .filter((z) => host === z || host.endsWith(`.${z}`))
    .sort((a, b) => b.length - a.length)[0];
  return `admin@${zone ?? host.split('.').slice(-2).join('.')}`;
}

class BadRequest extends Error {
  status = 400;
}

function str(v: unknown, field: string, max = 200): string {
  if (typeof v !== 'string' || !v.trim()) throw new BadRequest(`${field} is required`);
  if (v.length > max) throw new BadRequest(`${field} is too long`);
  return v.trim();
}

function strList(v: unknown): string[] {
  if (v === undefined || v === null || v === '') return [];
  const arr = Array.isArray(v) ? v : String(v).split(/[\s,]+/);
  return [...new Set(arr.map((x) => String(x).trim()).filter(Boolean))];
}

export function publicCert(c: Certificate, store: Store, busy: boolean) {
  const cred = store.get().credentials.find((x) => x.id === c.credentialId);
  return {
    id: c.id,
    domains: c.domains,
    credentialId: c.credentialId,
    email: c.email,
    credentialName: cred?.name ?? '(deleted)',
    acmeEnv: c.acmeEnv,
    keyType: c.keyType,
    status: busy ? 'issuing' : c.status,
    fingerprint: c.fingerprint,
    notBefore: c.notBefore,
    notAfter: c.notAfter,
    issuedAt: c.issuedAt,
    lastAttemptAt: c.lastAttemptAt,
    lastError: c.lastError,
    nextAttemptAt: c.nextAttemptAt,
    createdAt: c.createdAt,
  };
}

export function adminRouter(store: Store, vault: Vault, manager: CertManager): Router {
  const r = Router();
  const audit = (req: Request, action: string, target?: string, detail?: string) =>
    store.audit({ actor: 'admin', action, target, ip: clientIp(req), ok: true, detail });

  /* ---------- settings ---------- */

  r.get('/settings', (_req, res) => {
    res.json(store.get().settings);
  });

  r.put('/settings', async (req, res) => {
    const { renewBeforeDays } = req.body ?? {};
    if (renewBeforeDays !== undefined) {
      const n = Number(renewBeforeDays);
      if (!Number.isInteger(n) || n < 1 || n > 60) throw new BadRequest('renewBeforeDays must be 1–60');
    }
    await store.update((d) => {
      if (renewBeforeDays !== undefined) d.settings.renewBeforeDays = Number(renewBeforeDays);
    });
    await audit(req, 'settings.update');
    res.json(store.get().settings);
  });

  /* ---------- Cloudflare credentials ---------- */

  const publicCred = (c: CloudflareCredential) => ({
    id: c.id,
    name: c.name,
    hint: c.hint,
    zones: c.zones,
    lastVerifiedAt: c.lastVerifiedAt,
    createdAt: c.createdAt,
    certificates: store.get().certificates.filter((x) => x.credentialId === c.id).length,
  });

  r.get('/credentials', (_req, res) => {
    res.json(store.get().credentials.map(publicCred));
  });

  r.post('/credentials', async (req, res) => {
    const name = str(req.body?.name, 'name', 80);
    const token = str(req.body?.token, 'token', 500);
    let zones: string[];
    try {
      zones = await new Cloudflare(token).listZones();
    } catch (e) {
      throw new BadRequest(`Token rejected by Cloudflare: ${(e as Error).message}`);
    }
    const cred = await store.update((d) => {
      const c = {
        id: randomId(),
        name,
        token: vault.encrypt(token),
        hint: secretHint(token),
        zones,
        lastVerifiedAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      };
      d.credentials.push(c);
      return c;
    });
    await audit(req, 'credential.create', cred.id, name);
    res.status(201).json(publicCred(cred));
  });

  r.put('/credentials/:id', async (req, res) => {
    const existing = store.get().credentials.find((c) => c.id === req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const name = req.body?.name !== undefined ? str(req.body.name, 'name', 80) : undefined;
    const token = req.body?.token ? str(req.body.token, 'token', 500) : undefined;
    let zones: string[] | undefined;
    if (token) {
      try {
        zones = await new Cloudflare(token).listZones();
      } catch (e) {
        throw new BadRequest(`Token rejected by Cloudflare: ${(e as Error).message}`);
      }
    }
    const updated = await store.update((d) => {
      const c = d.credentials.find((x) => x.id === existing.id)!;
      if (name) c.name = name;
      if (token && zones) {
        c.token = vault.encrypt(token);
        c.hint = secretHint(token);
        c.zones = zones;
        c.lastVerifiedAt = new Date().toISOString();
      }
      return c;
    });
    await audit(req, 'credential.update', existing.id, token ? 'token rotated' : undefined);
    res.json(publicCred(updated));
  });

  r.post('/credentials/:id/verify', async (req, res) => {
    const existing = store.get().credentials.find((c) => c.id === req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    try {
      const zones = await new Cloudflare(vault.decrypt(existing.token)).listZones();
      const updated = await store.update((d) => {
        const c = d.credentials.find((x) => x.id === existing.id)!;
        c.zones = zones;
        c.lastVerifiedAt = new Date().toISOString();
        return c;
      });
      res.json({ ok: true, credential: publicCred(updated) });
    } catch (e) {
      res.status(400).json({ ok: false, error: (e as Error).message });
    }
  });

  r.delete('/credentials/:id', async (req, res) => {
    const id = req.params.id;
    if (!store.get().credentials.some((c) => c.id === id)) return res.status(404).json({ error: 'Not found' });
    const inUse = store.get().certificates.filter((c) => c.credentialId === id).map((c) => c.id);
    if (inUse.length) throw new BadRequest(`Credential is used by: ${inUse.join(', ')}. Reassign or delete those certificates first.`);
    await store.update((d) => {
      d.credentials = d.credentials.filter((c) => c.id !== id);
    });
    await audit(req, 'credential.delete', id);
    res.status(204).end();
  });

  /* ---------- certificates ---------- */

  r.get('/certs', (_req, res) => {
    res.json(store.get().certificates.map((c) => publicCert(c, store, manager.isBusy(c.id))));
  });

  r.post('/certs', async (req, res) => {
    const domains = strList(req.body?.domains).map((d) => d.toLowerCase());
    if (domains.length === 0) throw new BadRequest('At least one domain is required');
    if (domains.length > 100) throw new BadRequest('At most 100 domains per certificate');
    for (const d of domains) if (!HOSTNAME_RE.test(d)) throw new BadRequest(`Invalid domain: ${d}`);
    const id = domains[0]!;
    if (store.get().certificates.some((c) => c.id === id)) throw new BadRequest(`A certificate for ${id} already exists`);

    const credentialId = str(req.body?.credentialId, 'credentialId', 64);
    const cred = store.get().credentials.find((c) => c.id === credentialId);
    if (!cred) throw new BadRequest('Unknown Cloudflare credential');
    const email = req.body?.email ? String(req.body.email).trim().toLowerCase() : defaultEmail(id, cred.zones);
    if (!EMAIL_RE.test(email)) throw new BadRequest('Invalid email');
    const acmeEnv: AcmeEnv = req.body?.acmeEnv === 'staging' ? 'staging' : 'production';
    const keyType: KeyType = req.body?.keyType === 'rsa' ? 'rsa' : 'ecdsa';

    const cert = await store.update((d) => {
      const c: Certificate = {
        id,
        domains,
        credentialId,
        email,
        acmeEnv,
        keyType,
        status: 'pending',
        failures: 0,
        createdAt: new Date().toISOString(),
      };
      d.certificates.push(c);
      return c;
    });
    await audit(req, 'cert.create', id, domains.join(','));
    void manager.issue(id, 'initial issuance').catch(() => {});
    res.status(202).json(publicCert(cert, store, true));
  });

  r.put('/certs/:id', async (req, res) => {
    const existing = store.get().certificates.find((c) => c.id === req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { credentialId, acmeEnv, keyType, email } = req.body ?? {};
    if (credentialId !== undefined && !store.get().credentials.some((c) => c.id === credentialId))
      throw new BadRequest('Unknown Cloudflare credential');
    if (email !== undefined && email !== '' && !EMAIL_RE.test(String(email))) throw new BadRequest('Invalid email');
    const updated = await store.update((d) => {
      const c = d.certificates.find((x) => x.id === existing.id)!;
      if (credentialId) c.credentialId = credentialId;
      if (acmeEnv === 'staging' || acmeEnv === 'production') c.acmeEnv = acmeEnv;
      if (keyType === 'rsa' || keyType === 'ecdsa') c.keyType = keyType;
      if (email !== undefined) {
        const cred = d.credentials.find((x) => x.id === c.credentialId);
        c.email = email ? String(email).trim().toLowerCase() : defaultEmail(c.id, cred?.zones ?? []);
      }
      return c;
    });
    await audit(req, 'cert.update', existing.id);
    res.json(publicCert(updated, store, manager.isBusy(updated.id)));
  });

  r.post('/certs/:id/renew', async (req, res) => {
    const id = req.params.id;
    if (!store.get().certificates.some((c) => c.id === id)) return res.status(404).json({ error: 'Not found' });
    await audit(req, 'cert.renew_requested', id);
    void manager.issue(id, 'manual renewal').catch(() => {});
    res.status(202).json({ ok: true });
  });

  r.delete('/certs/:id', async (req, res) => {
    const id = req.params.id;
    if (!store.get().certificates.some((c) => c.id === id)) return res.status(404).json({ error: 'Not found' });
    await store.update((d) => {
      d.certificates = d.certificates.filter((c) => c.id !== id);
    });
    await audit(req, 'cert.delete', id);
    res.status(204).end();
  });

  /* ---------- API keys ---------- */

  const publicKey = (k: ApiKey) => {
    const { hash: _hash, ...rest } = k;
    return rest;
  };

  r.get('/keys', (_req, res) => {
    res.json(store.get().apiKeys.map(publicKey));
  });

  r.post('/keys', async (req, res) => {
    const name = str(req.body?.name, 'name', 80);
    const domains = strList(req.body?.domains).map((d) => d.toLowerCase());
    if (domains.length === 0) throw new BadRequest('Select at least one certificate (or "*" for all)');
    const allowedIps = strList(req.body?.allowedIps);
    for (const ip of allowedIps) if (!validateIpRule(ip)) throw new BadRequest(`Invalid IP/CIDR: ${ip}`);
    let expiresAt: string | undefined;
    if (req.body?.expiresInDays) {
      const n = Number(req.body.expiresInDays);
      if (!Number.isFinite(n) || n <= 0) throw new BadRequest('expiresInDays must be positive');
      expiresAt = new Date(Date.now() + n * 86_400_000).toISOString();
    }
    const token = randomToken('cs');
    const key = await store.update((d) => {
      const k = {
        id: randomId(),
        name,
        prefix: token.slice(0, 9),
        hash: hashToken(token),
        domains,
        allowedIps,
        expiresAt,
        createdAt: new Date().toISOString(),
      };
      d.apiKeys.push(k);
      return k;
    });
    await audit(req, 'apikey.create', key.id, name);
    // The plaintext key is only ever returned here.
    res.status(201).json({ ...publicKey(key), key: token });
  });

  r.delete('/keys/:id', async (req, res) => {
    const id = req.params.id;
    if (!store.get().apiKeys.some((k) => k.id === id)) return res.status(404).json({ error: 'Not found' });
    await store.update((d) => {
      d.apiKeys = d.apiKeys.filter((k) => k.id !== id);
    });
    await audit(req, 'apikey.revoke', id);
    res.status(204).end();
  });

  /* ---------- audit ---------- */

  r.get('/audit', (_req, res) => {
    res.json([...store.get().audit].reverse().slice(0, 300));
  });

  return r;
}
