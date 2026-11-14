import type {
  IncidentInput,
  ExtractedIOC,
  IOCType,
} from "../types/incident.ts";
import { IANA_TLDS } from "./tlds.ts";

const patterns: Record<IOCType, RegExp> = {
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  domain:
    /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  url: /\bhttps?:\/\/[^\s"'<>]+/gi,
  hash: /\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g,
};

// Suffixes used on internal networks that are not in the IANA root zone.
// Internal hostnames (e.g. wiki.corp.local) are still useful IOCs/assets.
const PRIVATE_SUFFIXES = new Set([
  "local", "localdomain", "lan", "internal", "intranet", "corp", "home",
]);

// A dotted token only counts as a domain when its last label is a real TLD.
// This rejects file names (payload.exe, invoice.pdf) and code tokens
// (http.server, os.path) without a hand-kept extension list. Extensions that
// are also live TLDs (.zip, .mov, .sh, .py) still count as domains on purpose:
// dropping them would hide real malicious domains.
function hasKnownTld(value: string): boolean {
  const tld = value.slice(value.lastIndexOf(".") + 1).toLowerCase();
  return IANA_TLDS.has(tld) || PRIVATE_SUFFIXES.has(tld);
}

function isValidIPv4(value: string): boolean {
  const parts = value.split(".").map(Number);

  return (
    parts.length === 4 &&
    parts.every(
      (part) => Number.isInteger(part) && part >= 0 && part <= 255
    )
  );
}

function classify(value: string): IOCType | null {
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(value)) {
    return "hash";
  }

  if (/^https?:\/\//i.test(value)) {
    return "url";
  }

  if (isValidIPv4(value)) {
    return "ip";
  }

  if (
    /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(
      value
    )
  ) {
    return hasKnownTld(value) ? "domain" : null;
  }

  return null;
}

export function extractIOCs(
  incident: IncidentInput
): ExtractedIOC[] {
  const sources = [
    {
      name: "description",
      text: incident.description,
    },
    ...(incident.observables ?? []).map((text, index) => ({
      name: `observable-${index + 1}`,
      text,
    })),
    ...(incident.evidence ?? []).map((text, index) => ({
      name: `evidence-${index + 1}`,
      text,
    })),
  ];

  const results = new Map<string, ExtractedIOC>();

  for (const source of sources) {
    for (const [type, pattern] of Object.entries(patterns) as [
      IOCType,
      RegExp
    ][]) {
      const matches = source.text.match(pattern) ?? [];

      for (const raw of matches) {
        const value = raw.replace(/[),.;]+$/, "");
        const detectedType = classify(value);

        if (detectedType !== type) continue;

        const key = `${detectedType}:${value.toLowerCase()}`;

        if (!results.has(key)) {
          results.set(key, {
            value,
            type: detectedType,
            source: source.name,
          });
        }
      }
    }
  }

  return [...results.values()];
}