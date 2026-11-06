import { EventEmitter } from 'node:events';
import { Store, type Certificate } from './store.js';
import { Vault, certFingerprint } from './crypto.js';
import { Cloudflare } from './cloudflare.js';
import { createAccountKey, issueCertificate } from './acme.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/**
 * Issues and renews certificates. Emits "issued" (certId) after a successful
 * issuance so listeners (e.g. our own HTTPS server) can reload.
 */
export class CertManager extends EventEmitter {
  private inProgress = new Map<string, Promise<void>>();
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly store: Store,
    private readonly vault: Vault,
    private readonly checkIntervalHours: number,
  ) {
    super();
  }

  needsRenewal(c: Certificate, now = Date.now()): boolean {
    if (!c.cert || !c.notAfter) return true;
    const notAfter = new Date(c.notAfter).getTime();
    const lifetime = c.notBefore ? notAfter - new Date(c.notBefore).getTime() : 90 * DAY;
    // Renew at N days before expiry, or when 1/3 of the lifetime remains (Let's Encrypt's
    // recommendation; matters for short-lived certs), whichever comes first.
    const renewBefore = Math.max(this.store.get().settings.renewBeforeDays * DAY, lifetime / 3);
    return notAfter - now < renewBefore;
  }

  isBusy(id: string): boolean {
    return this.inProgress.has(id);
  }

  /** Start issuing in the background; returns the promise for callers that want to wait. */
  issue(id: string, reason: string): Promise<void> {
    const existing = this.inProgress.get(id);
    if (existing) return existing;
    const p = this.doIssue(id, reason).finally(() => this.inProgress.delete(id));
    this.inProgress.set(id, p);
    return p;
  }

  private log(id: string, msg: string) {
    console.log(`[cert ${id}] ${msg}`);
  }

  private async getAccount(env: Certificate['acmeEnv'], email: string) {
    let account = this.store.get().accounts.find((a) => a.env === env && a.email === email);
    if (!account) {
      const key = await createAccountKey();
      account = await this.store.update((d) => {
        const a = { env, email, key: this.vault.encrypt(key) };
        d.accounts.push(a);
        return a;
      });
    }
    return { key: this.vault.decrypt(account.key), url: account.url };
  }

  private async doIssue(id: string, reason: string): Promise<void> {
    const cert = this.store.get().certificates.find((c) => c.id === id);
    if (!cert) throw new Error(`Unknown certificate ${id}`);
    const cred = this.store.get().credentials.find((c) => c.id === cert.credentialId);

    await this.store.update((d) => {
      const c = d.certificates.find((x) => x.id === id);
      if (c) {
        c.status = 'issuing';
        c.lastAttemptAt = new Date().toISOString();
      }
    });
    this.log(id, `Issuing (${reason}) via Let's Encrypt ${cert.acmeEnv} for ${cert.domains.join(', ')} (account ${cert.email})`);

    try {
      if (!cred) throw new Error('The Cloudflare credential assigned to this certificate no longer exists');
      const account = await this.getAccount(cert.acmeEnv, cert.email);
      const result = await issueCertificate({
        domains: cert.domains,
        env: cert.acmeEnv,
        email: cert.email,
        accountKey: account.key,
        accountUrl: account.url,
        cloudflare: new Cloudflare(this.vault.decrypt(cred.token)),
        keyType: cert.keyType,
        log: (m) => this.log(id, m),
      });

      await this.store.update((d) => {
        const acc = d.accounts.find((a) => a.env === cert.acmeEnv && a.email === cert.email);
        if (acc) acc.url = result.accountUrl;
        const c = d.certificates.find((x) => x.id === id);
        if (!c) return; // deleted meanwhile
        c.status = 'valid';
        c.cert = result.cert;
        c.chain = result.chain;
        c.privateKey = this.vault.encrypt(result.privateKey);
        c.fingerprint = certFingerprint(result.cert);
        c.notBefore = result.notBefore.toISOString();
        c.notAfter = result.notAfter.toISOString();
        c.issuedAt = new Date().toISOString();
        c.lastError = undefined;
        c.failures = 0;
        c.nextAttemptAt = undefined;
        d.audit.push({ at: new Date().toISOString(), actor: 'system', action: 'cert.issued', target: id, ok: true, detail: reason });
      });
      this.log(id, `Issued, valid until ${result.notAfter.toISOString()}`);
      this.emit('issued', id);
    } catch (e) {
      const message = (e as Error).message || String(e);
      this.log(id, `Failed: ${message}`);
      await this.store.update((d) => {
        const c = d.certificates.find((x) => x.id === id);
        if (!c) return;
        c.failures += 1;
        c.lastError = message;
        // Keep serving the previous certificate if it is still valid.
        const stillValid = c.cert && c.notAfter && new Date(c.notAfter).getTime() > Date.now();
        c.status = stillValid ? 'valid' : 'error';
        const backoff = Math.min(DAY, HOUR * 2 ** (c.failures - 1));
        c.nextAttemptAt = new Date(Date.now() + backoff).toISOString();
        d.audit.push({ at: new Date().toISOString(), actor: 'system', action: 'cert.issue_failed', target: id, ok: false, detail: message });
      });
      throw e;
    }
  }

  /** Renew everything that is due (sequentially, to be gentle on CA rate limits). */
  async tick(): Promise<void> {
    const now = Date.now();
    for (const c of this.store.get().certificates) {
      if (!this.needsRenewal(c, now)) continue;
      if (c.nextAttemptAt && new Date(c.nextAttemptAt).getTime() > now) continue;
      await this.issue(c.id, c.cert ? 'scheduled renewal' : 'initial issuance').catch(() => {});
    }
  }

  start(): void {
    // A crash mid-issuance leaves status "issuing"; reset it.
    void this.store.update((d) => {
      for (const c of d.certificates) if (c.status === 'issuing') c.status = c.cert ? 'valid' : 'pending';
    });
    setTimeout(() => void this.tick(), 5_000).unref();
    this.timer = setInterval(() => void this.tick(), this.checkIntervalHours * HOUR);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }
}
