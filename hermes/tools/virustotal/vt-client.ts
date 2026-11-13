const env = {
  vtBaseUrl: process.env.VT_BASE_URL ?? "https://www.virustotal.com/api/v3",
  vtApiKey: process.env.VT_API_KEY ?? "<VIRUSTOTAL_API_KEY>",
  vtTimeoutMs: Number(process.env.VT_TIMEOUT_MS ?? 15000),
};

export class VirusTotalClient {
  private async request<T>(path: string): Promise<T> {
    if (!env.vtApiKey) {
      throw new Error("VT_API_KEY belum diset");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), env.vtTimeoutMs);

    try {
      const response = await fetch(`${env.vtBaseUrl}${path}`, {
        method: "GET",
        headers: {
          "x-apikey": env.vtApiKey,
          accept: "application/json",
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        const error = new Error(
          `VirusTotal HTTP ${response.status}`
        ) as Error & { status?: number; retryAfter?: string };

        error.status = response.status;
        error.retryAfter = response.headers.get("retry-after") ?? undefined;

        throw error;
      }

      return (await response.json()) as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  getIP(ip: string) {
    return this.request<any>(`/ip_addresses/${encodeURIComponent(ip)}`);
  }

  getDomain(domain: string) {
    return this.request<any>(`/domains/${encodeURIComponent(domain)}`);
  }

  getHash(hash: string) {
    return this.request<any>(`/files/${encodeURIComponent(hash)}`);
  }

  getURL(url: string) {
    const id = Buffer.from(url, "utf8")
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    return this.request<any>(`/urls/${encodeURIComponent(id)}`);
  }
}