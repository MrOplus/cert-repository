import * as acme from 'acme-client';
import type { AcmeEnv, KeyType } from './store.js';
import { Cloudflare } from './cloudflare.js';

export interface IssueOptions {
  domains: string[];
  env: AcmeEnv;
  email?: string;
  accountKey: string;
  accountUrl?: string;
  cloudflare: Cloudflare;
  keyType: KeyType;
  log: (msg: string) => void;
}

export interface IssuedCertificate {
  privateKey: string;
  cert: string;
  chain: string;
  notBefore: Date;
  notAfter: Date;
  accountUrl: string;
}

export async function createAccountKey(): Promise<string> {
  return (await acme.crypto.createPrivateEcdsaKey('P-256')).toString();
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function issueCertificate(opts: IssueOptions): Promise<IssuedCertificate> {
  const { domains, cloudflare, log } = opts;
  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt[opts.env],
    accountKey: opts.accountKey,
    accountUrl: opts.accountUrl,
  });

  const key =
    opts.keyType === 'rsa'
      ? await acme.crypto.createPrivateRsaKey(2048)
      : await acme.crypto.createPrivateEcdsaKey('P-256');

  const [, csr] = await acme.crypto.createCsr({ commonName: domains[0], altNames: domains }, key);

  // Records created for this order, keyed by keyAuthorization so they can be cleaned up.
  const created = new Map<string, { zoneId: string; recordId: string }>();

  const fullchain = await client.auto({
    csr,
    email: opts.email,
    termsOfServiceAgreed: true,
    challengePriority: ['dns-01'],
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      if (challenge.type !== 'dns-01') throw new Error(`Unsupported challenge ${challenge.type}`);
      const name = `_acme-challenge.${authz.identifier.value}`;
      const zone = await cloudflare.findZone(authz.identifier.value);
      log(`Creating TXT ${name} in zone ${zone.name}`);
      const recordId = await cloudflare.createTxtRecord(zone.id, name, keyAuthorization);
      created.set(keyAuthorization, { zoneId: zone.id, recordId });
      // Give Cloudflare's authoritative nameservers a moment to pick up the record.
      await sleep(10_000);
    },
    challengeRemoveFn: async (authz, _challenge, keyAuthorization) => {
      const rec = created.get(keyAuthorization);
      if (!rec) return;
      log(`Removing TXT _acme-challenge.${authz.identifier.value}`);
      try {
        await cloudflare.deleteRecord(rec.zoneId, rec.recordId);
      } catch (e) {
        log(`Warning: failed to remove TXT record: ${(e as Error).message}`);
      }
      created.delete(keyAuthorization);
    },
  });

  const [leaf, ...rest] = acme.crypto.splitPemChain(fullchain);
  if (!leaf) throw new Error('CA returned an empty certificate chain');
  const info = acme.crypto.readCertificateInfo(leaf);

  return {
    privateKey: key.toString(),
    cert: leaf.trim() + '\n',
    chain: rest.map((c) => c.trim() + '\n').join(''),
    notBefore: info.notBefore,
    notAfter: info.notAfter,
    accountUrl: client.getAccountUrl(),
  };
}
