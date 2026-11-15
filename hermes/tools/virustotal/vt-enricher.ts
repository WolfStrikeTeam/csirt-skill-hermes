import type {
  ExtractedIOC,
  IOCEnrichment,
} from "../../types/incident.js";

import { VirusTotalClient } from "./vt-client.js";

export class IOCEnricher {
  constructor(private readonly vt: VirusTotalClient) {}

  async enrich(ioc: ExtractedIOC): Promise<IOCEnrichment> {
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

      const attributes = result?.data?.attributes ?? {};

      const stats = attributes.last_analysis_stats ?? {};
      const verdict =
        (stats.malicious ?? 0) > 0
          ? "malicious"
          : (stats.suspicious ?? 0) > 0
            ? "suspicious"
            : Object.keys(stats).length > 0
              ? "benign"
              : "unknown";

      return {
        value: ioc.value,
        type: ioc.type,
        verdict,
        source: "VirusTotal",
        attributes: {
          last_analysis_stats: stats,
          last_analysis_date: attributes.last_analysis_date ?? null,
          reputation: attributes.reputation ?? null,
          tags: attributes.tags ?? [],
          categories: attributes.categories ?? {},
          country: attributes.country ?? null,
          as_owner: attributes.as_owner ?? null,
          asn: attributes.asn ?? null,
          meaningful_name: attributes.meaningful_name ?? null,
          names: attributes.names ?? [],
        },
      };
    } catch (error) {
      return {
        value: ioc.value,
        type: ioc.type,
        verdict: "unknown",
        source: "VirusTotal",
        attributes: {},
        error:
          error instanceof Error ? error.message : "Unknown error",
      };
    }
  }
}