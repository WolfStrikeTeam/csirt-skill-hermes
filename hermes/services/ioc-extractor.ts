import type {
  IncidentInput,
  ExtractedIOC,
  IOCType,
} from "../types/incident.ts";

const patterns: Record<IOCType, RegExp> = {
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  domain:
    /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  url: /\bhttps?:\/\/[^\s"'<>]+/gi,
  hash: /\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g,
};

// File extensions that are not real TLDs. Without this, "payload.exe" or
// "invoice.pdf" in alert text matches the domain pattern. Extensions that are
// also live TLDs (.zip, .mov, .sh, .py) are left out on purpose: dropping them
// would hide real malicious domains.
const FILE_EXTENSIONS = new Set([
  "exe", "dll", "sys", "drv", "ocx", "cpl", "scr", "msi", "bat", "cmd",
  "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "jar", "apk", "dmg",
  "elf", "bin", "dat", "tmp", "log", "txt", "ini", "cfg", "conf", "iso",
  "img", "rar", "gz", "tgz", "tar", "doc", "docx", "docm", "xls", "xlsx",
  "xlsm", "ppt", "pptx", "pdf", "html", "htm", "php", "asp", "aspx", "jsp",
  "json", "xml", "csv",
]);

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
    const tld = value.slice(value.lastIndexOf(".") + 1).toLowerCase();
    if (FILE_EXTENSIONS.has(tld)) return null;
    return "domain";
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