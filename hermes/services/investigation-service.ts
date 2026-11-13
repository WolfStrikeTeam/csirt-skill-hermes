import type { IncidentInput } from "../types/incident.ts";
import { normalizeIncident } from "./incident-normalizer.ts";
import { extractIOCs } from "./ioc-extractor.ts";
import { IOCValidator } from "../tools/virustotal/vt.validator.ts";
import { IOCEnricher } from "../tools/virustotal/vt.enricher.ts";

export class InvestigationService {
  constructor(
    private readonly validator: IOCValidator,
    private readonly enricher: IOCEnricher
  ) {}

  async investigate(input: IncidentInput) {
    // 1. Incident context
    const incident = normalizeIncident(input);

    // 2. IOC extraction
    const iocs = extractIOCs(incident);

    // 3. IOC validation
    const validation = await this.validator.validateBulk(iocs);

    // 4. Detailed enrichment untuk IOC yang perlu ditelusuri
    const enrichment = [];

    for (const result of validation) {
      if (
        result.verdict === "malicious" ||
        result.verdict === "suspicious"
      ) {
        const ioc = iocs.find(
          (item) =>
            item.value === result.value &&
            item.type === result.type
        );

        if (ioc) {
          enrichment.push(await this.enricher.enrich(ioc));
        }
      }
    }

    return {
      incident: {
        incidentId: incident.incidentId,
        source: incident.source,
        title: incident.title,
        severity: incident.severity ?? "unknown",
      },
      investigation: {
        extracted_ioc_count: iocs.length,
        validated_ioc_count: validation.length,
        enrichment_count: enrichment.length,
      },
      extracted_iocs: iocs,
      validation,
      enrichment,
      limitations: [
        "VirusTotal results are third-party intelligence, not definitive proof.",
        "No detection does not establish that an IOC is safe.",
        "This workflow performs passive lookups only.",
        "No containment, blocking, deletion, or remediation action was performed."
      ],
      generated_at: new Date().toISOString(),
    };
  }
}