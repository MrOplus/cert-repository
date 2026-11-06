import fs from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

export type AcmeEnv = 'production' | 'staging';
export type KeyType = 'ecdsa' | 'rsa';
export type CertStatus = 'pending' | 'issuing' | 'valid' | 'error';

export interface Settings {
  renewBeforeDays: number;
}

export interface CloudflareCredential {
  id: string;
  name: string;
  /** Encrypted API token. */
  token: string;
  hint: string;
  zones: string[];
  lastVerifiedAt?: string;
  createdAt: string;
}

export interface AcmeAccount {
  env: AcmeEnv;
  email: string;
  /** Encrypted account private key. */
  key: string;
  url?: string;
}

export interface Certificate {
  /** Primary domain, used as the identifier in the download API. */
  id: string;
  domains: string[];
  credentialId: string;
  /** ACME account contact email (defaults to admin@<zone>). */
  email: string;
  acmeEnv: AcmeEnv;
  keyType: KeyType;
  status: CertStatus;
  cert?: string;
  chain?: string;
  /** Encrypted private key. */
  privateKey?: string;
  fingerprint?: string;
  notBefore?: string;
  notAfter?: string;
  issuedAt?: string;
  lastAttemptAt?: string;
  lastError?: string;
  failures: number;
  nextAttemptAt?: string;
  createdAt: string;
}

export interface ApiKey {
  id: string;
  name: string;
  /** Display prefix, e.g. "cs_AbCd". */
  prefix: string;
  hash: string;
  /** Certificate ids this key can read; "*" for all. */
  domains: string[];
  /** Optional IP / CIDR allow-list; empty = any. */
  allowedIps: string[];
  expiresAt?: string;
  lastUsedAt?: string;
  lastUsedIp?: string;
  createdAt: string;
}

export interface AuditEntry {
  at: string;
  actor: string;
  action: string;
  target?: string;
  ip?: string;
  ok: boolean;
  detail?: string;
}

export interface Data {
  version: 1;
  settings: Settings;
  credentials: CloudflareCredential[];
  accounts: AcmeAccount[];
  certificates: Certificate[];
  apiKeys: ApiKey[];
  audit: AuditEntry[];
}

const MAX_AUDIT = 1000;

function empty(): Data {
  return {
    version: 1,
    settings: { renewBeforeDays: 30 },
    credentials: [],
    accounts: [],
    certificates: [],
    apiKeys: [],
    audit: [],
  };
}

/**
 * Small JSON-file store. All mutations are serialized and written atomically
 * (write temp file + rename) with 0600 permissions. Secrets inside are
 * encrypted by the caller via Vault.
 */
export class Store {
  private data: Data;
  private readonly file: string;
  private chain: Promise<void> = Promise.resolve();

  constructor(dir: string) {
    this.file = path.join(dir, 'store.json');
    this.data = existsSync(this.file)
      ? { ...empty(), ...(JSON.parse(readFileSync(this.file, 'utf8')) as Data) }
      : empty();
  }

  static async open(dir: string): Promise<Store> {
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    return new Store(dir);
  }

  get(): Readonly<Data> {
    return this.data;
  }

  /** Apply a mutation and persist. Mutations run one at a time. */
  update<T>(fn: (d: Data) => T): Promise<T> {
    const run = this.chain.then(async () => {
      const result = fn(this.data);
      if (this.data.audit.length > MAX_AUDIT) this.data.audit.splice(0, this.data.audit.length - MAX_AUDIT);
      const tmp = `${this.file}.${process.pid}.tmp`;
      await fs.writeFile(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
      await fs.rename(tmp, this.file);
      return result;
    });
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  audit(entry: Omit<AuditEntry, 'at'>): Promise<void> {
    return this.update((d) => {
      d.audit.push({ at: new Date().toISOString(), ...entry });
    });
  }
}
