import type { IndexerPage, PullRequest, WazuhAlertSource } from "./types.js";

export interface WazuhIndexerConfig {
  url: string;
  username?: string;
  password?: string;
  token?: string;
  timeoutMs?: number;
}

/** Indexer search API (port 9200), NOT the Wazuh Manager API (port 55000). */
export class WazuhIndexerClient implements WazuhAlertSource {
  private readonly base: URL;
  private readonly auth: string;
  private readonly timeoutMs: number;

  constructor(config: WazuhIndexerConfig) {
    let url: URL;
    try { url = new URL(config.url); } catch { throw new Error("WAZUH_INDEXER_URL tidak valid"); }
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
      throw new Error("Indexer wajib HTTPS, kecuali HTTP pada localhost untuk pengujian");
    }
    if (url.username || url.password || url.search || url.hash || url.pathname !== "/") {
      throw new Error("Indexer URL hanya boleh origin (contoh https://host:9200/), tanpa kredensial/path/query");
    }
    if (config.token && (config.username || config.password)) {
      throw new Error("Pilih token ATAU username/password, jangan keduanya");
    }
    if (config.token) this.auth = `Bearer ${config.token}`;
    else if (config.username && config.password) {
      this.auth = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`;
    } else throw new Error("Set WAZUH_INDEXER_TOKEN atau username/password");
    this.base = url;
    this.timeoutMs = config.timeoutMs ?? 10000;
    if (!Number.isInteger(this.timeoutMs) || this.timeoutMs < 1000 || this.timeoutMs > 60000) {
      throw new Error("timeoutMs harus 1000-60000");
    }
  }

  async search(request: Required<PullRequest>): Promise<IndexerPage> {
    const { since, min_rule_level: level, limit, offset } = request;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("limit harus 1-100");
    if (!Number.isInteger(offset) || offset < 0 || offset > 10000) throw new Error("offset harus 0-10000");
    if (!Number.isInteger(level) || level < 0 || level > 16) throw new Error("min_rule_level harus 0-16");
    if (!Number.isFinite(Date.parse(since))) throw new Error("since harus timestamp ISO 8601 valid");
    const url = new URL("/wazuh-alerts-*/_search", this.base);
    const body = {
      size: limit,
      from: offset,
      track_total_hits: true,
      sort: [{ timestamp: { order: "desc" } }],
      query: { bool: { filter: [
        { range: { timestamp: { gte: since } } },
        { range: { "rule.level": { gte: level } } },
      ] } },
      // Do not ingest full_log, raw log data, usernames, or credential fields.
      _source: [
        "id", "timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
        "agent.id", "agent.name", "agent.ip", "manager.name", "location",
        "data.srcip", "data.dstip", "data.src_ip", "data.dst_ip",
      ],
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { Authorization: this.auth, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      throw new Error(`Wazuh Indexer API gagal (HTTP ${response.status}). Periksa URL, kredensial, dan role read-only.`);
    }
    const length = Number(response.headers.get("content-length") ?? "0");
    if (length > 2 * 1024 * 1024) throw new Error("Indexer response terlalu besar");
    if (!response.body) throw new Error("Indexer response tidak memiliki body");
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    const reader = response.body.getReader();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        totalBytes += value.byteLength;
        if (totalBytes > 2 * 1024 * 1024) {
          await reader.cancel();
          throw new Error("Indexer response melebihi batas 2 MiB");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    let data: unknown;
    try { data = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { throw new Error("Indexer response bukan JSON valid"); }
    const root = data as { hits?: { hits?: unknown; total?: unknown } } | null;
    if (!root?.hits || !Array.isArray(root.hits.hits)) {
      throw new Error("Indexer response tidak mempunyai hits.hits");
    }
    const totalObj = root.hits.total;
    const total = typeof totalObj === "number" ? totalObj
      : typeof totalObj === "object" && totalObj !== null && "value" in totalObj
        ? Number((totalObj as {value: unknown}).value) : NaN;
    if (!Number.isInteger(total) || total < 0) throw new Error("Indexer hits.total tidak valid");
    return { hits: root.hits.hits as unknown[], total, offset };
  }
}

export function indexerFromEnv(env: NodeJS.ProcessEnv = process.env): WazuhIndexerClient {
  if (!env.WAZUH_INDEXER_URL) {
    throw new Error("WAZUH_INDEXER_URL belum diatur; untuk tes offline pakai fixture atau mock lokal");
  }
  return new WazuhIndexerClient({
    url: env.WAZUH_INDEXER_URL,
    username: env.WAZUH_INDEXER_USERNAME,
    password: env.WAZUH_INDEXER_PASSWORD,
    token: env.WAZUH_INDEXER_TOKEN,
  });
}
