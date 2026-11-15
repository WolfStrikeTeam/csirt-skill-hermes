import type {
  IncidentInput,
  ExtractedIOC,
  IOCType,
} from "../types/incident.js";
import { IANA_TLDS } from "./tlds.js";

const patterns: Record<IOCType, RegExp> = {
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  // Last label may contain digits (e.g. .i2p); hasKnownTld() filters the rest.
  domain:
    /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9]{1,62}\b/g,
  url: /\bhttps?:\/\/[^\s"'<>]+/gi,
  hash: /\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g,
};

// Suffixes that are not in the IANA root zone but still matter in incidents.
const EXTRA_SUFFIXES = new Set([
  // Overlay networks used by malware C2 and leak sites (RFC 7686 for .onion).
  "onion", "i2p", "bit",
  // Private-network names (.internal reserved by ICANN in 2024) and common
  // ad hoc ones, so internal hostnames such as wiki.corp.local are kept.
  "internal", "local", "localdomain", "lan", "intranet", "corp", "home",
  // Special-use names (RFC 6761), seen in lab data and test alerts.
  "test", "localhost", "example",
  // Operator additions without a code change, e.g. a TLD delegated after the
  // bundled snapshot or a company suffix: WOLFSTRIKE_EXTRA_TLDS=newtld,acme
  ...(process.env.WOLFSTRIKE_EXTRA_TLDS ?? "")
    .split(",")
    .map((s) => s.trim().replace(/^\./, "").toLowerCase())
    .filter(Boolean),
]);

// WOLFSTRIKE_TLD_CHECK=off accepts any dotted token as a domain (old
// behavior), for when missing a domain is worse than extra noise.
const TLD_CHECK = process.env.WOLFSTRIKE_TLD_CHECK?.toLowerCase() !== "off";

// A dotted token only counts as a domain when its last label is a real TLD
// (bundled IANA list, refreshed by `npm run update-tlds`) or an extra suffix.
// This rejects file names (payload.exe, invoice.pdf) and code tokens
// (http.server, os.path) without a hand-kept extension list. Extensions that
// are also live TLDs (.zip, .mov, .sh, .py) still count as domains on purpose:
// dropping them would hide real malicious domains.
function hasKnownTld(value: string): boolean {
  if (!TLD_CHECK) return true;
  const tld = value.slice(value.lastIndexOf(".") + 1).toLowerCase();
  return IANA_TLDS.has(tld) || EXTRA_SUFFIXES.has(tld);
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
    /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9]{1,62}$/.test(
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