import { MCPServer } from "mcp-use";

/**
 * WOLFSTRIKE: MCP server for incident response, called by an AI agent (Hermes).
 *
 * MVP modules (each one's output feeds the next):
 *   1. Incident Intake
 *   2. Incident Triage & Classification (incl. MITRE ATT&CK + Cyber Kill Chain)
 *   3. MITRE ATT&CK Mapping (standalone)
 *   4. Threat Investigation & IOC Enrichment
 *   5. Reporting & Response (block IP/IOC is the only executed remediation)
 *
 * Register tools for each module on `server` below.
 */
const server = new MCPServer({
  name: "wolfstrike-mcp",
  title: "WOLFSTRIKE",
  version: "0.1.0",
  description:
    "MCP server for incident response: intake, triage, MITRE ATT&CK mapping, IOC enrichment, and reporting.",
});

export default server;
