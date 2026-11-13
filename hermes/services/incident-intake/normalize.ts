import { createHash, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import type { IncidentCase, ReportInput } from "../../types/incident-intake.js";

const MAX_ALERT_BYTES = 128 * 1024;
const SRC_ID = /^[a-zA-Z0-9_.-]{1,64}$/;

type RecordValue = Record<string, unknown>;
function record(value: unknown): RecordValue | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as RecordValue : undefined;
}
function stringValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

/** One-line display text; omit raw logs and redact common high-risk secret patterns. */
export function safeText(value: unknown, maxLength = 256): string {
  const input = stringValue(value) ?? "";
  return input
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .replace(/\bBearer\s+[a-zA-Z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b(password|passwd|token|api[_-]?key|secret)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .replace(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi, "[REDACTED-EMAIL]")
    .replace(/\s+/g, " ").trim().slice(0, maxLength);
}

export function normalizedTime(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${name} wajib berupa timestamp ISO 8601`);
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})$/i.test(value)) {
    throw new Error(`${name} harus ISO 8601 dengan timezone`);
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new Error(`${name} bukan timestamp yang valid`);
  return new Date(ms).toISOString();
}

export function validateSourceId(sourceId: string): string {
  if (!SRC_ID.test(sourceId)) {
    throw new Error("source_id hanya boleh 1-64 karakter huruf, angka, _, ., atau -");
  }
  return sourceId;
}

function hashId(key: string): string {
  return `INC-${createHash("sha256").update(key).digest("hex").slice(0, 24).toUpperCase()}`;
}

function readableIp(value: unknown): string | undefined {
  return typeof value === "string" && isIP(value) !== 0 ? value : undefined;
}

/** Accept either a Wazuh alerts.json document or a Wazuh Indexer _search hit. */
export function normalizeWazuhAlert(input: unknown, sourceId: string, now = new Date()): IncidentCase {
  validateSourceId(sourceId);
  const serialized = JSON.stringify(input);
  if (!serialized || Buffer.byteLength(serialized, "utf8") > MAX_ALERT_BYTES) {
    throw new Error("Alert kosong atau melebihi batas 128 KiB");
  }
  const wrapper = record(input);
  if (!wrapper) throw new Error("Alert harus berupa objek JSON");
  const alert = (record(wrapper._source) ?? wrapper);
  const rule = record(alert.rule);
  if (!rule) throw new Error("Wazuh alert tidak memiliki field rule");
  const ruleId = stringValue(rule.id)?.trim();
  const ruleLevel = rule.level;
  if (!ruleId || ruleId.length > 64) throw new Error("rule.id hilang/tidak valid");
  if (!Number.isInteger(ruleLevel) || typeof ruleLevel !== "number" || ruleLevel < 0 || ruleLevel > 16) {
    throw new Error("rule.level harus integer 0-16");
  }
  const occurred = normalizedTime(alert.timestamp, "alert.timestamp");
  const agent = record(alert.agent);
  const data = record(alert.data);
  const manager = record(alert.manager);

  const indexName = stringValue(wrapper._index);
  const hitId = stringValue(wrapper._id);
  const alertId = stringValue(alert.id);
  const externalId = indexName && hitId
    ? `${indexName}/${hitId}`
    : alertId?.trim() || createHash("sha256")
        .update(JSON.stringify({ occurred, ruleId, agentId: agent?.id, data: { srcip: data?.srcip, dstip: data?.dstip } }))
        .digest("hex");
  if (externalId.length > 512) throw new Error("Wazuh external ID terlalu panjang");

  const rawAgentIp = readableIp(agent?.ip);
  const agentInfo = agent ? {
    ...(stringValue(agent.id) ? { id: safeText(agent.id, 64) } : {}),
    ...(stringValue(agent.name) ? { name: safeText(agent.name, 128) } : {}),
    ...(rawAgentIp ? { ip: rawAgentIp } : {}),
  } : undefined;
  const groups = Array.isArray(rule.groups)
    ? rule.groups.filter((g): g is string => typeof g === "string").slice(0, 20).map((g) => safeText(g, 64))
    : [];
  const description = safeText(rule.description, 512) || `Wazuh rule ${ruleId} triggered`;
  const sourceIp = readableIp(data?.srcip) ?? readableIp(data?.src_ip);
  const destinationIp = readableIp(data?.dstip) ?? readableIp(data?.dst_ip);

  return {
    schema_version: "1.0",
    case_id: hashId(`wazuh\0${sourceId}\0${externalId}`),
    source: { type: "wazuh", instance: sourceId, external_id: externalId },
    status: "new",
    classification_status: "pending",
    created_at: now.toISOString(),
    occurred_at: occurred,
    title: safeText(`Wazuh rule ${ruleId}: ${description}`, 200),
    description,
    observables: {
      ...(sourceIp ? { source_ip: sourceIp } : {}),
      ...(destinationIp ? { destination_ip: destinationIp } : {}),
    },
    wazuh: {
      rule_id: ruleId,
      rule_level: ruleLevel,
      groups,
      ...(agentInfo && Object.keys(agentInfo).length > 0 ? { agent: agentInfo } : {}),
      ...(typeof manager?.name === "string" ? { manager: safeText(manager.name, 128) } : {}),
      ...(typeof alert.location === "string" ? { location: safeText(alert.location, 256) } : {}),
    },
  };
}

/** This receives a forwarded email/manual report; it does NOT read an email inbox. */
export function normalizeReport(input: ReportInput, now = new Date()): IncidentCase {
  if (input.channel !== "manual" && input.channel !== "email") throw new Error("channel tidak valid");
  if (typeof input.title !== "string" || !input.title.trim()) throw new Error("title wajib diisi");
  if (typeof input.description !== "string" || !input.description.trim()) throw new Error("description wajib diisi");
  if (input.title.length > 200 || input.description.length > 4000) throw new Error("Panjang laporan melebihi batas");
  const reference = input.external_reference?.trim();
  if (reference && reference.length > 128) throw new Error("external_reference terlalu panjang");
  const externalId = reference || randomUUID();
  return {
    schema_version: "1.0",
    case_id: hashId(`${input.channel}\0forwarded\0${externalId}`),
    source: { type: input.channel, instance: "forwarded", external_id: externalId },
    status: "new",
    classification_status: "pending",
    created_at: now.toISOString(),
    occurred_at: input.occurred_at ? normalizedTime(input.occurred_at, "occurred_at") : now.toISOString(),
    title: safeText(input.title, 200),
    description: safeText(input.description, 4000),
    observables: {},
  };
}
