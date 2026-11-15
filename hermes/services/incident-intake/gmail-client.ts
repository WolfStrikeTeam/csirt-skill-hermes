/** Gmail API read-only transport. No mailbox mutation, no arbitrary URL fetching. */
export interface GmailBody { data?: string; attachmentId?: string; size?: number }
export interface GmailPart {
  mimeType?: string;
  filename?: string;
  headers?: Array<{ name?: string; value?: string }>;
  body?: GmailBody;
  parts?: GmailPart[];
}
export interface GmailMessage {
  id: string;
  threadId?: string;
  internalDate?: string;
  payload?: GmailPart;
}
export interface GmailList { messages?: Array<{ id: string; threadId?: string }>; nextPageToken?: string }
export interface GmailApi {
  list(limit: number, pageToken?: string): Promise<GmailList>;
  get(id: string): Promise<GmailMessage>;
  attachment(messageId: string, attachmentId: string): Promise<GmailBody>;
}

export interface GmailConfig {
  accessToken?: string;
  clientId?: string;
  clientSecret?: string;
  refreshToken?: string;
  query: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}
const GMAIL_ID = /^[a-zA-Z0-9_-]{1,128}$/;
const GMAIL_ATTACHMENT_ID = /^[a-zA-Z0-9_-]{1,4096}$/;
const MAX_API_BYTES = 8 * 1024 * 1024;

function safeBaseUrl(input: string): URL {
  const url = new URL(input);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.origin !== "https://gmail.googleapis.com" && !(url.protocol === "http:" && local)) {
    throw new Error("Gmail API endpoint tidak diizinkan (hanya Gmail resmi atau HTTP loopback untuk tes)");
  }
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error("Gmail API base URL harus origin saja");
  }
  return url;
}

export class GmailApiClient implements GmailApi {
  private readonly base: URL;
  private readonly doFetch: typeof fetch;
  private readonly timeout: number;
  private token?: string;
  private tokenExpires = 0;
  constructor(private readonly config: GmailConfig) {
    this.base = safeBaseUrl(config.baseUrl ?? "https://gmail.googleapis.com/");
    this.doFetch = config.fetchImpl ?? fetch;
    this.timeout = config.timeoutMs ?? 10000;
    if (!Number.isInteger(this.timeout) || this.timeout < 1000 || this.timeout > 60000) {
      throw new Error("Gmail timeout harus antara 1000-60000 ms");
    }
    if (!config.query || config.query.length > 250 || /[\r\n\x00]/.test(config.query)) {
      throw new Error("GMAIL_QUERY wajib diisi, maksimum 250 karakter (contoh: label:CSIRT)");
    }
    if (!config.accessToken && !(config.refreshToken && config.clientId && config.clientSecret)) {
      throw new Error("Gmail OAuth belum dikonfigurasi; isi token atau client_id/client_secret/refresh_token");
    }
  }

  private async getToken(): Promise<string> {
    if (this.config.accessToken) return this.config.accessToken;
    if (this.token && Date.now() < this.tokenExpires - 60000) return this.token;
    // Google OAuth token endpoint fixed, never forwarded to caller-supplied hosts.
    const body = new URLSearchParams({
      client_id: this.config.clientId!,
      client_secret: this.config.clientSecret!,
      refresh_token: this.config.refreshToken!,
      grant_type: "refresh_token",
    });
    const response = await this.doFetch("https://oauth2.googleapis.com/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body, redirect: "error", signal: AbortSignal.timeout(this.timeout),
    });
    if (!response.ok) throw new Error(`OAuth refresh gagal (HTTP ${response.status})`);
    const parsed = await response.json() as { access_token?: unknown; expires_in?: unknown };
    if (typeof parsed.access_token !== "string" || !parsed.access_token) {
      throw new Error("OAuth tidak mengembalikan access_token");
    }
    this.token = parsed.access_token;
    this.tokenExpires = Date.now() + (typeof parsed.expires_in === "number" ? parsed.expires_in : 3600) * 1000;
    return this.token;
  }

  private async readJson(path: string, params?: Record<string, string>): Promise<unknown> {
    const url = new URL(path, this.base);
    for (const [k, v] of Object.entries(params ?? {})) url.searchParams.set(k, v);
    const response = await this.doFetch(url, {
      method: "GET", redirect: "error",
      headers: { Authorization: `Bearer ${await this.getToken()}`, Accept: "application/json" },
      signal: AbortSignal.timeout(this.timeout),
    });
    if (!response.ok) throw new Error(`Gmail API gagal (HTTP ${response.status})`);
    if (!response.body) throw new Error("Gmail API response kosong");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > MAX_API_BYTES) {
          await reader.cancel();
          throw new Error("Gmail API response melebihi 8 MiB");
        }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { throw new Error("Gmail API mengembalikan JSON tidak valid"); }
  }

  async list(limit: number, pageToken?: string): Promise<GmailList> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 10) throw new Error("limit Gmail 1-10");
    if (pageToken !== undefined && (!pageToken || pageToken.length > 1024 || /[\r\n\x00]/.test(pageToken))) {
      throw new Error("Gmail page_token tidak valid");
    }
    const result = await this.readJson("/gmail/v1/users/me/messages", {
      q: this.config.query, maxResults: String(limit), includeSpamTrash: "false",
      ...(pageToken ? { pageToken } : {}),
    });
    if (!result || typeof result !== "object") throw new Error("Daftar pesan Gmail tidak valid");
    const data = result as GmailList;
    if (data.messages !== undefined && (!Array.isArray(data.messages) || data.messages.length > limit)) {
      throw new Error("Daftar pesan Gmail tidak sesuai skema");
    }
    if (data.nextPageToken !== undefined && (typeof data.nextPageToken !== "string" || data.nextPageToken.length > 1024)) {
      throw new Error("Gmail nextPageToken tidak valid");
    }
    for (const item of data.messages ?? []) {
      if (!item || typeof item.id !== "string" || !GMAIL_ID.test(item.id)) {
        throw new Error("ID pesan Gmail tidak valid");
      }
    }
    return data;
  }

  async get(id: string): Promise<GmailMessage> {
    if (!GMAIL_ID.test(id)) throw new Error("ID pesan Gmail tidak valid");
    const data = await this.readJson(`/gmail/v1/users/me/messages/${id}`, { format: "full" });
    if (!data || typeof data !== "object" || (data as GmailMessage).id !== id) {
      throw new Error("Detail pesan Gmail tidak valid");
    }
    return data as GmailMessage;
  }

  async attachment(messageId: string, attachmentId: string): Promise<GmailBody> {
    if (!GMAIL_ID.test(messageId) || !GMAIL_ATTACHMENT_ID.test(attachmentId)) {
      throw new Error("ID lampiran Gmail tidak valid");
    }
    const data = await this.readJson(`/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}`);
    if (!data || typeof data !== "object" || typeof (data as GmailBody).data !== "string") {
      throw new Error("Lampiran Gmail tidak memiliki data");
    }
    return data as GmailBody;
  }
}

export function gmailFromEnv(env: NodeJS.ProcessEnv = process.env): GmailApiClient {
  return new GmailApiClient({
    accessToken: env.GMAIL_ACCESS_TOKEN,
    clientId: env.GMAIL_CLIENT_ID,
    clientSecret: env.GMAIL_CLIENT_SECRET,
    refreshToken: env.GMAIL_REFRESH_TOKEN,
    query: env.GMAIL_QUERY ?? "",
    baseUrl: env.GMAIL_API_BASE_URL,
  });
}
