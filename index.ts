import { MCPServer, text } from "mcp-use"; // atau "mcp-use" sesuai versi package.json kamu
import { z } from "zod";

import { VirusTotalClient } from "./hermes/tools/virustotal/vt-client.ts";
import { IOCValidator } from "./hermes/tools/virustotal/vt-validator.ts";
import { IOCEnricher } from "./hermes/tools/virustotal/vt-enricher.ts";
import { InvestigationService } from "./hermes/services/investigation-service.ts";
import { extractIOCs } from "./hermes/services/ioc-extractor.ts";

// Inisialisasi dependensi VirusTotal & Investigation Service
const vt = new VirusTotalClient();
const validator = new IOCValidator(vt);
const enricher = new IOCEnricher(vt);
const investigation = new InvestigationService(validator, enricher);

/**
 * WOLFSTRIKE: MCP server for incident response, called by an AI agent (Hermes).
 *
 * MVP modules (each one's output feeds the next):
 *   1. Incident Intake
 *   2. Incident Triage & Classification (incl. MITRE ATT&CK + Cyber Kill Chain)
 *   3. MITRE ATT&CK Mapping (standalone)
 *   4. Threat Investigation & IOC Enrichment
 *   5. Reporting & Response (block IP/IOC is the only executed remediation)
 */
const server = new MCPServer({
  name: "wolfstrike-mcp",
  title: "WOLFSTRIKE",
  version: "0.1.0",
  description:
    "MCP server for incident response: intake, triage, MITRE ATT&CK mapping, IOC enrichment, and reporting.",
});

// ============================================================================
// MODULE 1: Incident Intake
// ============================================================================
server.tool(
  {
    name: "intake_incident",
    description:
      "Ingest and normalize raw incident alerts from Wazuh, TheHive, or manual input, extracting initial IOCs.",
    schema: z.object({
      incidentId: z.string().min(1),
      source: z.enum(["thehive", "wazuh", "manual"]),
      title: z.string().min(1),
      description: z.string(),
      severity: z.string().optional(),
      timestamp: z.string().optional(),
      observables: z.array(z.string()).optional(),
      evidence: z.array(z.string()).optional(),
    }),
  },
  async (args) => {
    const extracted = extractIOCs({
      incidentId: args.incidentId,
      source: args.source,
      title: args.title,
      description: args.description,
      observables: args.observables,
      evidence: args.evidence,
    });

    const intakePayload = {
      status: "ingested",
      incident: {
        id: args.incidentId,
        source: args.source,
        title: args.title,
        description: args.description,
        severity: args.severity ?? "unknown",
        timestamp: args.timestamp ?? new Date().toISOString(),
      },
      extractedIOCs: extracted,
    };

    return text(JSON.stringify(intakePayload, null, 2));
  }
);

// ============================================================================
// MODULE 2: Incident Triage & Classification (incl. MITRE ATT&CK + Kill Chain)
// ============================================================================
server.tool(
  {
    name: "triage_incident",
    description:
      "Triage and classify an incident by severity, false-positive likelihood, Cyber Kill Chain phase, and initial MITRE ATT&CK tactics.",
    schema: z.object({
      incidentId: z.string().min(1),
      title: z.string().min(1),
      description: z.string(),
      severity: z.string().optional(),
      extractedIOCs: z.array(z.string()).optional(),
    }),
  },
  async (args) => {
    // Placeholder logic: dapat dihubungkan ke TriageService di masa mendatang
    const triageResult = {
      incidentId: args.incidentId,
      classification: "Suspicious Activity",
      recommendedSeverity: args.severity ?? "medium",
      cyberKillChainPhase: "Command and Control / Exploitation",
      initialMitreTactics: ["TA0001 - Initial Access", "TA0011 - Command and Control"],
      readyForInvestigation: true,
      summary: `Triaged incident '${args.title}' with ${args.extractedIOCs?.length ?? 0} observables.`,
    };

    return text(JSON.stringify(triageResult, null, 2));
  }
);

// ============================================================================
// MODULE 3: MITRE ATT&CK Mapping (Standalone)
// ============================================================================
server.tool(
  {
    name: "map_mitre_attack",
    description:
      "Map observed behaviors, logs, or TTP descriptions to specific MITRE ATT&CK Tactics and Techniques.",
    schema: z.object({
      behaviorDescription: z.string().min(1),
      evidence: z.array(z.string()).optional(),
    }),
  },
  async ({ behaviorDescription, evidence }) => {
    // Placeholder logic: dapat dihubungkan ke rule/embedding mapper MITRE ATT&CK
    const mappingResult = {
      input: behaviorDescription,
      evidenceCount: evidence?.length ?? 0,
      mappings: [
        {
          tactic: "Execution",
          tacticId: "TA0002",
          technique: "Command and Scripting Interpreter",
          techniqueId: "T1059",
          confidence: "medium",
        },
      ],
    };

    return text(JSON.stringify(mappingResult, null, 2));
  }
);

// ============================================================================
// MODULE 4: Threat Investigation & IOC Enrichment (Dari kode sentinel-csirt)
// ============================================================================

// 4A. Investigasi Lengkap (Extract -> Validate -> Enrich)
server.tool(
  {
    name: "investigate_incident",
    description:
      "Investigate an incident by extracting, validating, and enriching its IOCs via VirusTotal.",
    schema: z.object({
      incidentId: z.string().min(1),
      source: z.enum(["thehive", "wazuh", "manual"]),
      title: z.string().min(1),
      description: z.string(),
      severity: z.string().optional(),
      timestamp: z.string().optional(),
      observables: z.array(z.string()).optional(),
      evidence: z.array(z.string()).optional(),
    }),
  },
  async (args) => {
    const result = await investigation.investigate(args);
    return text(JSON.stringify(result, null, 2));
  }
);

// 4B. Ekstraksi IOC Saja
server.tool(
  {
    name: "extract_iocs",
    description: "Extract and deduplicate IOCs from incident text and evidence.",
    schema: z.object({
      description: z.string(),
      observables: z.array(z.string()).optional(),
      evidence: z.array(z.string()).optional(),
    }),
  },
  async (args) => {
    const result = extractIOCs({
      incidentId: "extraction-only",
      source: "manual",
      title: "IOC extraction",
      description: args.description,
      observables: args.observables,
      evidence: args.evidence,
    });
    return text(JSON.stringify(result, null, 2));
  }
);

// 4C. Validasi Bulk IOC
server.tool(
  {
    name: "validate_iocs",
    description:
      "Validate existing IPs, domains, URLs, and file hashes using passive VirusTotal lookups.",
    schema: z.object({
      iocs: z
        .array(
          z.object({
            value: z.string().min(1),
            type: z.enum(["ip", "domain", "url", "hash"]),
          })
        )
        .min(1)
        .max(20),
    }),
  },
  async ({ iocs }) => {
    const result = await validator.validateBulk(
      iocs.map((ioc) => ({
        ...ioc,
        source: "manual",
      }))
    );
    return text(JSON.stringify(result, null, 2));
  }
);

// 4D. Enrichment Single IOC
server.tool(
  {
    name: "enrich_ioc",
    description:
      "Retrieve additional passive VirusTotal attributes for an existing IOC.",
    schema: z.object({
      value: z.string().min(1),
      type: z.enum(["ip", "domain", "url", "hash"]),
    }),
  },
  async ({ value, type }) => {
    const result = await enricher.enrich({
      value,
      type,
      source: "manual",
    });
    return text(JSON.stringify(result, null, 2));
  }
);

// ============================================================================
// MODULE 5: Reporting & Response (Block IP/IOC)
// ============================================================================
server.tool(
  {
    name: "respond_and_report",
    description:
      "Generate an executive/technical incident report and execute containment by blocking confirmed malicious IPs/IOCs.",
    schema: z.object({
      incidentId: z.string().min(1),
      summary: z.string().min(1),
      mitreTechniques: z.array(z.string()).optional(),
      iocsToBlock: z
        .array(
          z.object({
            value: z.string().min(1),
            type: z.enum(["ip", "domain", "url", "hash"]),
          })
        )
        .optional(),
      executeBlock: z.boolean().default(false),
    }),
  },
  async ({ incidentId, summary, mitreTechniques, iocsToBlock, executeBlock }) => {
    // Catatan: Hubungkan ke Firewall / Wazuh Active Response / EDR API jika executeBlock === true
    const blockedActions =
      executeBlock && iocsToBlock?.length
        ? iocsToBlock.map((ioc) => ({
            ioc: ioc.value,
            type: ioc.type,
            action: "BLOCKED",
            timestamp: new Date().toISOString(),
          }))
        : [];

    const report = {
      incidentId,
      generatedAt: new Date().toISOString(),
      executiveSummary: summary,
      mitreAttackMapped: mitreTechniques ?? [],
      remediationExecuted: executeBlock,
      blockedIOCs: blockedActions,
    };

    return text(JSON.stringify(report, null, 2));
  }
);

export default server;