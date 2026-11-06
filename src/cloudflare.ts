const API = 'https://api.cloudflare.com/client/v4';

interface CfResponse<T> {
  success: boolean;
  errors: { code: number; message: string }[];
  result: T;
  result_info?: { page: number; total_pages: number };
}

interface Zone {
  id: string;
  name: string;
  status: string;
}

export class CloudflareError extends Error {}

export class Cloudflare {
  private zoneCache = new Map<string, Zone>();

  constructor(private readonly token: string) {}

  private async req<T>(method: string, path: string, body?: unknown): Promise<CfResponse<T>> {
    const res = await fetch(`${API}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    let json: CfResponse<T>;
    try {
      json = (await res.json()) as CfResponse<T>;
    } catch {
      throw new CloudflareError(`Cloudflare API ${method} ${path}: HTTP ${res.status}`);
    }
    if (!res.ok || !json.success) {
      const msg = json.errors?.map((e) => `${e.code}: ${e.message}`).join('; ') || `HTTP ${res.status}`;
      throw new CloudflareError(`Cloudflare API ${method} ${path} failed: ${msg}`);
    }
    return json;
  }

  /** Validates the token by listing the zones it can access. */
  async listZones(): Promise<string[]> {
    const names: string[] = [];
    for (let page = 1; page <= 50; page++) {
      const r = await this.req<Zone[]>('GET', `/zones?per_page=50&page=${page}`);
      names.push(...r.result.map((z) => z.name));
      if (!r.result_info || page >= r.result_info.total_pages) break;
    }
    return names.sort();
  }

  /** Finds the zone that contains the given hostname (longest match). */
  async findZone(hostname: string): Promise<Zone> {
    const labels = hostname.replace(/^\*\./, '').split('.');
    for (let i = 0; i <= labels.length - 2; i++) {
      const candidate = labels.slice(i).join('.');
      const cached = this.zoneCache.get(candidate);
      if (cached) return cached;
      const r = await this.req<Zone[]>('GET', `/zones?name=${encodeURIComponent(candidate)}`);
      const zone = r.result.find((z) => z.name === candidate);
      if (zone) {
        this.zoneCache.set(candidate, zone);
        return zone;
      }
    }
    throw new CloudflareError(`No Cloudflare zone accessible with this token for ${hostname}`);
  }

  async createTxtRecord(zoneId: string, name: string, content: string): Promise<string> {
    const r = await this.req<{ id: string }>('POST', `/zones/${zoneId}/dns_records`, {
      type: 'TXT',
      name,
      content: `"${content}"`,
      ttl: 60,
      comment: 'certstore ACME challenge (temporary)',
    });
    return r.result.id;
  }

  async deleteRecord(zoneId: string, recordId: string): Promise<void> {
    await this.req('DELETE', `/zones/${zoneId}/dns_records/${recordId}`);
  }
}
