/** Public contract for the Incident Intake -> Triage handoff, v1. */
export type IncidentSource = "wazuh" | "manual" | "email";

export interface IncidentCase {
  schema_version: "1.0";
  case_id: string;
  source: {
    type: IncidentSource;
    instance: string;
    external_id: string;
  };
  status: "new";
  classification_status: "pending";
  created_at: string;
  occurred_at: string;
  title: string;
  description: string;
  observables: { source_ip?: string; destination_ip?: string };
  wazuh?: {
    rule_id: string;
    rule_level: number;
    groups: string[];
    agent?: { id?: string; name?: string; ip?: string };
    manager?: string;
    location?: string;
  };
}

export interface IntakeResult {
  status: "created" | "existing";
  incident_case: IncidentCase;
}

export interface ReportInput {
  channel: "email" | "manual";
  title: string;
  description: string;
  occurred_at?: string;
  external_reference?: string;
}

export interface PullRequest {
  since?: string;
  min_rule_level?: number;
  limit?: number;
  offset?: number;
}

export interface PullResult {
  source: "wazuh";
  fetched: number;
  created: number;
  existing: number;
  rejected: number;
  failures: string[];
  total_hits: number;
  offset: number;
  next_offset: number | null;
  cases: IntakeResult[];
}

export interface IndexerPage {
  hits: unknown[];
  total: number;
  offset: number;
}

export interface WazuhAlertSource {
  search(request: Required<PullRequest>): Promise<IndexerPage>;
}
