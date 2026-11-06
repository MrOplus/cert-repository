import crypto from 'node:crypto';

const VERSION = 'v1';

/** AES-256-GCM encryption for secrets at rest (Cloudflare tokens, private keys). */
export class Vault {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32) throw new Error('Vault key must be 32 bytes');
  }

  encrypt(plain: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${VERSION}:${Buffer.concat([iv, tag, ct]).toString('base64')}`;
  }

  decrypt(payload: string): string {
    const [version, data] = payload.split(':', 2);
    if (version !== VERSION || !data) throw new Error('Unsupported ciphertext format');
    const buf = Buffer.from(data, 'base64');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  }
}

/** API keys are 256-bit random values, so a fast hash is sufficient (no brute-force risk). */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** Constant-time string comparison (length-independent). */
export function safeEqual(a: string, b: string): boolean {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

export function randomToken(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(32).toString('base64url')}`;
}

export function randomId(): string {
  return crypto.randomBytes(8).toString('hex');
}

/** Show only enough of a secret to recognise it. */
export function secretHint(secret: string): string {
  if (secret.length <= 12) return '••••';
  return `${secret.slice(0, 6)}…${secret.slice(-4)}`;
}

export function certFingerprint(pem: string): string {
  return new crypto.X509Certificate(pem).fingerprint256.replace(/:/g, '').toLowerCase();
}
