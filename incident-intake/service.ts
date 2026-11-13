import { normalizeReport, normalizeWazuhAlert, normalizedTime, validateSourceId } from "./normalize.js";
import { IncidentStore } from "./store.js";
import type { IncidentCase, IntakeResult, PullRequest, PullResult, ReportInput, WazuhAlertSource } from "./types.js";

export class IncidentIntakeService {
  constructor(
    private readonly store: IncidentStore,
    private readonly sourceId: string,
    private readonly alertSource?: WazuhAlertSource,
  ) { validateSourceId(sourceId); }

  async intakeWazuh(alert: unknown, sourceId = this.sourceId): Promise<IntakeResult> {
    return this.store.createOrGet(normalizeWazuhAlert(alert, sourceId));
  }

  async intakeReport(report: ReportInput): Promise<IntakeResult> {
    return this.store.createOrGet(normalizeReport(report));
  }

  async getIncident(caseId: string): Promise<IncidentCase | null> {
    return this.store.get(caseId);
  }

  async listIncidents(limit = 50): Promise<IncidentCase[]> {
    return this.store.list(limit);
  }

  async collect(request: PullRequest): Promise<PullResult> {
    if (!this.alertSource) throw new Error("Wazuh Indexer tidak dikonfigurasi");
    const fromTime = request.since ?? new Date(Date.now() - 15 * 60000).toISOString();
    const since = normalizedTime(fromTime, "since");
    const limit = request.limit ?? 50;
    const offset = request.offset ?? 0;
    const min_rule_level = request.min_rule_level ?? 3;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("limit harus 1-100");
    if (!Number.isInteger(offset) || offset < 0 || offset > 10000) throw new Error("offset harus 0-10000");
    if (!Number.isInteger(min_rule_level) || min_rule_level < 0 || min_rule_level > 16) {
      throw new Error("min_rule_level harus 0-16");
    }
    const page = await this.alertSource.search({ since, min_rule_level, limit, offset });
    const cases: IntakeResult[] = [];
    const failures: string[] = [];
    let created = 0, existing = 0;
    for (let i = 0; i < page.hits.length; i++) {
      try {
        const result = await this.intakeWazuh(page.hits[i]);
        cases.push(result);
        if (result.status === "created") created++;
        else existing++;
      } catch (error) {
        // Only log record number/error type; never include raw attacker-controlled log lines.
        const msg = error instanceof Error ? error.message : "Unknown error";
        failures.push(`hit[${offset + i}]: ${msg}`);
      }
    }
    return {
      source: "wazuh", fetched: page.hits.length, created, existing,
      rejected: failures.length, failures, total_hits: page.total,
      offset,
      next_offset: offset + page.hits.length < page.total ? offset + page.hits.length : null,
      cases,
    };
  }
}
