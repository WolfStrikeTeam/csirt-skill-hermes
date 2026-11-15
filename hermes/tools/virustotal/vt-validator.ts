import type {
  ExtractedIOC,
  IOCValidation,
  IOCVerdict,
} from "../../types/incident.ts";

import { VirusTotalClient } from "./vt-client.js";

export class IOCValidator {
  constructor(private readonly vt: VirusTotalClient) {}

  private getStats(data: any) {
    return data?.data?.attributes?.last_analysis_stats ?? null;
  }

  private getVerdict(stats: any): IOCVerdict {
    if (!stats) return "unknown";

    if ((stats.malicious ?? 0) > 0) return "malicious";
    if ((stats.suspicious ?? 0) > 0) return "suspicious";

    return "benign";
  }

  async validate(ioc: ExtractedIOC): Promise<IOCValidation> {
    try {
      let result: any;

      switch (ioc.type) {
        case "ip":
          result = await this.vt.getIP(ioc.value);
          break;
        case "domain":
          result = await this.vt.getDomain(ioc.value);
          break;
        case "hash":
          result = await this.vt.getHash(ioc.value);
          break;
        case "url":
          result = await this.vt.getURL(ioc.value);
          break;
      }

      const stats = this.getStats(result);

      if (!stats) {
        return {
          value: ioc.value,
          type: ioc.type,
          verdict: "unknown",
          malicious: null,
          suspicious: null,
          undetected: null,
          total: null,
          source: "VirusTotal",
        };
      }

      // Jumlah total harus menjumlahkan semua kategori statistik,
      // bukan hanya malicious/undetected.
      const total = Object.values(stats).reduce<number>(
        (sum, value) =>
          sum + (typeof value === "number" ? value : 0),
        0
      );

      return {
        value: ioc.value,
        type: ioc.type,
        verdict: this.getVerdict(stats),
        malicious: stats.malicious ?? 0,
        suspicious: stats.suspicious ?? 0,
        undetected: stats.undetected ?? 0,
        total,
        source: "VirusTotal",
      };
    } catch (error) {
      const status = (error as { status?: number }).status;

      return {
        value: ioc.value,
        type: ioc.type,
        verdict: status === 429 ? "deferred" : "unknown",
        malicious: null,
        suspicious: null,
        undetected: null,
        total: null,
        source: "VirusTotal",
        error:
          error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  async validateBulk(iocs: ExtractedIOC[]) {
    const results: IOCValidation[] = [];

    // Sengaja sequential untuk menghindari burst request.
    // Tambahkan rate limiter sesuai kuota akun VT yang sebenarnya.
    for (const ioc of iocs) {
      results.push(await this.validate(ioc));
    }

    return results;
  }
}