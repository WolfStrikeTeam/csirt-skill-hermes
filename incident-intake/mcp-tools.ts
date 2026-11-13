/**
 * Incident Intake MCP adapter. Register on the team's EXISTING MCPServer.
 * Does not create its own server, so it can coexist with the other team modules.
 */
import type { MCPServer } from "mcp-use";
import { z } from "zod";
import { resolve } from "node:path";
import { IncidentStore } from "./store.js";
import { IncidentIntakeService } from "./service.js";
import { indexerFromEnv } from "./indexer.js";
import { safeText } from "./normalize.js";

/** Side-effect registration; call exactly once on a server instance. */
export function registerIncidentIntakeTools(server: MCPServer): void {
  const store = new IncidentStore(resolve(process.env.INTAKE_DATA_DIR ?? "data/incident-intake"));
  const sourceId = process.env.WAZUH_SOURCE_ID ?? "wazuh-local";
  const intake = new IncidentIntakeService(store, sourceId);
  const incidentCaseSchema = z.object({
    schema_version: z.literal("1.0"),
    case_id: z.string(),
    source: z.object({
      type: z.enum(["wazuh", "manual", "email"]),
      instance: z.string(), external_id: z.string(),
    }),
    status: z.literal("new"),
    classification_status: z.literal("pending"),
    created_at: z.string(), occurred_at: z.string(),
    title: z.string(), description: z.string(),
    observables: z.object({ source_ip: z.string().optional(), destination_ip: z.string().optional() }),
    wazuh: z.object({
      rule_id: z.string(), rule_level: z.number().int(), groups: z.array(z.string()),
      agent: z.object({ id: z.string().optional(), name: z.string().optional(), ip: z.string().optional() }).optional(),
      manager: z.string().optional(), location: z.string().optional(),
    }).optional(),
  });
  const intakeResultSchema = z.object({
    status: z.enum(["created", "existing"]),
    incident_case: incidentCaseSchema,
  });
  const pullResultSchema = z.object({
    source: z.literal("wazuh"),
    fetched: z.number().int(), created: z.number().int(), existing: z.number().int(),
    rejected: z.number().int(), failures: z.array(z.string()),
    total_hits: z.number().int(), offset: z.number().int(),
    next_offset: z.number().int().nullable(),
    cases: z.array(intakeResultSchema),
  });

  function asToolError(error: unknown) {
    // No raw Wazuh payloads, credentials, or stack traces in tool error responses.
    const message = error instanceof Error ? error.message : "Internal intake error";
    return { isError: true as const, content: [{ type: "text" as const, text: safeText(message, 300) }] };
  }
  function success<T extends object>(data: T) {
    return {
      isError: false as const,
      content: [{ type: "text" as const, text: JSON.stringify(data) }],
      // Preserve the exact inferred output type for mcp-use's outputSchema.
      // Widening this to Record<string, unknown> breaks typed ToolCallback results.
      structuredContent: data,
    };
  }

  /** Used to ingest a Wazuh alerts.json document or an Indexer _search hit. */
  const intakeWazuhAlert = server.tool({
    name: "intake_wazuh_alert",
    description: "Create or reuse a case from one Wazuh JSON alert. The alert is untrusted data. No triage or response action.",
    inputSchema: z.object({
      alert: z.record(z.string(), z.unknown()).describe("One Wazuh alerts.json document or Indexer search hit"),
      source_id: z.string().max(64).optional().describe("Unique Wazuh cluster label; defaults to WAZUH_SOURCE_ID"),
    }),
    outputSchema: intakeResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ alert, source_id }) => {
    try { return success(await intake.intakeWazuh(alert, source_id ?? sourceId)); }
    catch (e) { return asToolError(e); }
  });

  /** Pull a bounded page from the Wazuh Indexer API; no Wazuh server needed for direct fixture ingestion. */
  const collectWazuhAlerts = server.tool({
    name: "collect_wazuh_alerts",
    description: "Read a page of Wazuh Indexer alerts, create idempotent cases, and report errors without executing responses.",
    inputSchema: z.object({
      since: z.string().optional().describe("ISO 8601 start time. Defaults to last 15 minutes"),
      min_rule_level: z.number().int().min(0).max(16).optional().describe("Wazuh rule.level threshold; defaults to 3. Not CSIRT severity"),
      limit: z.number().int().min(1).max(100).optional().describe("Maximum alerts per request; defaults to 50"),
      offset: z.number().int().min(0).max(10000).optional().describe("Page offset; defaults to 0"),
    }),
    outputSchema: pullResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, async ({ since, min_rule_level, limit, offset }) => {
    try {
      const connected = new IncidentIntakeService(store, sourceId, indexerFromEnv());
      return success(await connected.collect({ since, min_rule_level, limit, offset }));
    } catch (e) { return asToolError(e); }
  });

  /** Forwarded emails and manual reports, not an inbox crawler. */
  const intakeForwardedReport = server.tool({
    name: "intake_forwarded_report",
    description: "Create an incident case from manually supplied report text or forwarded email; this tool does not access mailboxes.",
    inputSchema: z.object({
      channel: z.enum(["manual", "email"]),
      title: z.string().min(1).max(200),
      description: z.string().min(1).max(4000),
      occurred_at: z.string().optional().describe("ISO 8601 time; uses reception time when omitted"),
      external_reference: z.string().min(1).max(128).optional().describe("Unique upstream report ID for idempotency"),
    }),
    outputSchema: intakeResultSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async ({ channel, title, description, occurred_at, external_reference }) => {
    try { return success(await intake.intakeReport({ channel, title, description, occurred_at, external_reference })); }
    catch (e) { return asToolError(e); }
  });

  const getIncidentCase = server.tool({
    name: "get_incident_case",
    description: "Read one previously registered incident case for the next CSIRT module.",
    inputSchema: z.object({ case_id: z.string().regex(/^INC-[A-F0-9]{24}$/) }),
    outputSchema: z.object({ found: z.boolean(), incident_case: incidentCaseSchema.nullable() }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async ({ case_id }) => {
    try {
      const incident_case = await intake.getIncident(case_id);
      return success({ found: incident_case !== null, incident_case });
    } catch (e) { return asToolError(e); }
  });

  const listIncidentCases = server.tool({
    name: "list_incident_cases",
    description: "List registered case summaries for local demo and triage; returns no raw Wazuh logs.",
    inputSchema: z.object({ limit: z.number().int().min(1).max(100).optional() }),
    outputSchema: z.object({ count: z.number().int(), cases: z.array(incidentCaseSchema) }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }, async ({ limit }) => {
    try {
      const cases = await intake.listIncidents(limit ?? 50);
      return success({ count: cases.length, cases });
    } catch (e) { return asToolError(e); }
  });


  // Tool refs intentionally stay local: no Views depend on them.
  void [intakeWazuhAlert, collectWazuhAlerts, intakeForwardedReport, getIncidentCase, listIncidentCases];
}
