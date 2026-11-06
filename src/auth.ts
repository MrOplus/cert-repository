import net from 'node:net';
import type { Request, Response, NextFunction } from 'express';
import type { Store, ApiKey } from './store.js';
import { hashToken, safeEqual } from './crypto.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      apiKey?: ApiKey;
    }
  }
}

export function clientIp(req: Request): string {
  const ip = req.ip || req.socket.remoteAddress || '';
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function bearer(req: Request): string | undefined {
  const h = req.get('authorization');
  if (h?.toLowerCase().startsWith('bearer ')) return h.slice(7).trim();
  return req.get('x-api-key')?.trim() || undefined;
}

/* ---------- brute-force protection ---------- */

const WINDOW_MS = 15 * 60_000;
const MAX_FAILURES = 10;
const failures = new Map<string, { count: number; first: number }>();

function isLockedOut(ip: string): boolean {
  const f = failures.get(ip);
  if (!f) return false;
  if (Date.now() - f.first > WINDOW_MS) {
    failures.delete(ip);
    return false;
  }
  return f.count >= MAX_FAILURES;
}

function recordFailure(ip: string) {
  const f = failures.get(ip);
  if (!f || Date.now() - f.first > WINDOW_MS) failures.set(ip, { count: 1, first: Date.now() });
  else f.count++;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, f] of failures) if (now - f.first > WINDOW_MS) failures.delete(ip);
}, 60_000).unref();

/* ---------- IP allow-lists ---------- */

export function validateIpRule(rule: string): boolean {
  const [addr, bits] = rule.split('/');
  const family = net.isIP(addr ?? '');
  if (!family) return false;
  if (bits === undefined) return true;
  const n = Number(bits);
  return Number.isInteger(n) && n >= 0 && n <= (family === 4 ? 32 : 128);
}

function ipAllowed(ip: string, rules: string[]): boolean {
  if (rules.length === 0) return true;
  const family = net.isIP(ip);
  if (!family) return false;
  const list = new net.BlockList();
  for (const rule of rules) {
    const [addr, bits] = rule.split('/') as [string, string | undefined];
    const type = net.isIP(addr) === 6 ? 'ipv6' : 'ipv4';
    if (bits === undefined) list.addAddress(addr, type);
    else list.addSubnet(addr, Number(bits), type);
  }
  return list.check(ip, family === 6 ? 'ipv6' : 'ipv4');
}

/* ---------- middleware ---------- */

export function requireAdmin(store: Store, adminToken: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = clientIp(req);
    if (isLockedOut(ip)) return res.status(429).json({ error: 'Too many failed attempts, try again later' });
    const token = bearer(req);
    if (!token || !safeEqual(token, adminToken)) {
      recordFailure(ip);
      void store.audit({ actor: 'admin', action: 'auth.failed', ip, ok: false });
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  };
}

export function requireApiKey(store: Store) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const ip = clientIp(req);
    if (isLockedOut(ip)) return res.status(429).json({ error: 'Too many failed attempts, try again later' });
    const token = bearer(req);
    const hash = token ? hashToken(token) : '';
    const key = token ? store.get().apiKeys.find((k) => safeEqual(k.hash, hash)) : undefined;

    let reason: string | undefined;
    if (!key) reason = 'invalid key';
    else if (key.expiresAt && new Date(key.expiresAt).getTime() < Date.now()) reason = 'expired key';
    else if (!ipAllowed(ip, key.allowedIps)) reason = 'ip not allowed';

    if (reason || !key) {
      recordFailure(ip);
      void store.audit({ actor: key ? `key:${key.name}` : 'anonymous', action: 'api.auth_failed', ip, ok: false, detail: reason });
      return res.status(401).json({ error: 'Unauthorized' });
    }

    req.apiKey = key;
    await store.update((d) => {
      const k = d.apiKeys.find((x) => x.id === key.id);
      if (k) {
        k.lastUsedAt = new Date().toISOString();
        k.lastUsedIp = ip;
      }
    });
    next();
  };
}

export function keyCanAccess(key: ApiKey, certId: string): boolean {
  return key.domains.includes('*') || key.domains.includes(certId);
}
