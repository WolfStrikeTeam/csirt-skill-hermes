export type IncidentSource = "thehive" | "wazuh" | "manual";

export interface IncidentInput {
  incidentId: string;
  source: IncidentSource;
  title: string;
  description: string;
  severity?: string;
  timestamp?: string;

  // Observable atau indikator yang sudah disediakan sumber.
  observables?: string[];

  // Evidence berupa teks/log yang dapat dianalisis.
  evidence?: string[];
}

export type IOCType = "ip" | "domain" | "url" | "hash";

export type IOCVerdict =
  | "malicious"
  | "suspicious"
  | "benign"
  | "unknown"
  | "deferred";

export interface ExtractedIOC {
  value: string;
  type: IOCType;
  source: string;
}

export interface IOCValidation {
  value: string;
  type: IOCType;
  verdict: IOCVerdict;
  malicious: number | null;
  suspicious: number | null;
  undetected: number | null;
  total: number | null;
  source: "VirusTotal";
  error?: string;
}

export interface IOCEnrichment {
  value: string;
  type: IOCType;
  verdict: IOCVerdict;
  attributes: Record<string, unknown>;
  source: "VirusTotal";
  error?: string;
}