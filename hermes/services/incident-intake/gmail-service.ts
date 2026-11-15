/** Pull Gmail reports, parse bounded body/attachments, extract *candidate* IOCs, persist cases. */
import { createHash } from "node:crypto";
import type { GmailApi, GmailMessage } from "./gmail-client.js";
import { parseGmailReport } from "./gmail-parser.js";
import { extractIocCandidates } from "./ioc-candidates.js";
import { IncidentStore } from "./store.js";
import { safeText, validateSourceId } from "./normalize.js";
import type { IncidentCase, IntakeResult } from "../../types/incident-intake.js";

export interface GmailPullResult {
  source: "gmail";
  fetched: number;
  created: number;
  existing: number;
  rejected: number;
  failures: string[];
  has_more: boolean;
  next_page_token: string | null;
  cases: IntakeResult[];
}

export class GmailIntakeService {
  constructor(
    private readonly store: IncidentStore,
    private readonly client: GmailApi,
    private readonly mailboxId = "csirt-gmail",
  ) { validateSourceId(mailboxId); }

  async pull(limit = 5, pageToken?: string): Promise<GmailPullResult> {
    if (!Number.isInteger(limit) || limit < 1 || limit > 10) throw new Error("Gmail limit harus 1-10");
    const page = await this.client.list(limit, pageToken);
    const cases: IntakeResult[] = [];
    const failures: string[] = [];
    let created = 0, existing = 0;
    const processed = new Set<string>();
    for (const [index, item] of (page.messages ?? []).entries()) {
      if (processed.has(item.id)) continue;
      processed.add(item.id);
      try {
        const message: GmailMessage = await this.client.get(item.id);
        const report = await parseGmailReport(message, this.client);
        const iocs = extractIocCandidates(report.sources);
        // The deterministic preview is not an AI analysis or final incident classification.
        const rawBody = report.sources.filter(s => s.name === "body").map(s => s.text).join(" ");
        const rawDocs = report.sources.filter(s => s.name.startsWith("attachment:")).map(s => s.text).join(" ");
        const contextualPreview = safeText([rawBody, rawDocs].filter(Boolean).join(" | "), 3000)
          || "Email contains no readable report text";
        const caseId = "INC-" + createHash("sha256")
          .update(`gmail\0${this.mailboxId}\0${report.gmail_id}`).digest("hex").slice(0, 24).toUpperCase();
        const incident: IncidentCase = {
          schema_version: "1.0",
          case_id: caseId,
          source: { type: "email", instance: this.mailboxId, external_id: report.gmail_id },
          status: "new", classification_status: "pending",
          created_at: new Date().toISOString(),
          occurred_at: report.occurred_at,
          title: safeText(report.subject, 200),
          description: contextualPreview,
          observables: { ...(iocs.ips[0] ? { source_ip: iocs.ips[0] } : {}) },
          email: {
            gmail_message_id: report.gmail_id,
            ...(report.thread_id ? { thread_id: report.thread_id } : {}),
            sender_redacted: report.sender,
            attachments: report.attachments,
            context_excerpt: contextualPreview,
          },
          ioc_candidates: iocs,
        };
        const result = await this.store.createOrGet(incident);
        cases.push(result);
        if (result.status === "created") created++;
        else existing++;
      } catch {
        failures.push(`message[${index}]: could-not-ingest`);
      }
    }
    return { source: "gmail", fetched: (page.messages ?? []).length, created, existing,
      rejected: failures.length, failures, has_more: Boolean(page.nextPageToken),
      next_page_token: page.nextPageToken ?? null, cases };
  }
}
