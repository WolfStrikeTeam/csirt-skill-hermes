/** Preliminary IOC extraction. Never claims an IOC is malicious or verified. */
import { isIP } from "node:net";

export type IocKind = "ip" | "domain" | "url" | "md5" | "sha256";
export interface IocEvidence { kind: IocKind; value: string; found_in: string }
export interface IocCandidates {
  ips: string[];
  domains: string[];
  urls: string[];
  hashes_md5: string[];
  hashes_sha256: string[];
  evidence: IocEvidence[];
}

const urlRegex = /https?:\/\/[^\s<>"'`\[\]()]+/gi;
const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
const ipv4Regex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const hashRegex = /\b(?:[a-f0-9]{64}|[a-f0-9]{32})\b/gi;

export function extractIocCandidates(sources: Array<{ name: string; text: string }>): IocCandidates {
  const ips = new Set<string>();
  const domains = new Set<string>();
  const urls = new Set<string>();
  const md5 = new Set<string>();
  const sha256 = new Set<string>();
  const evidence: IocEvidence[] = [];
  const seenEvidence = new Set<string>();
  const add = (kind: IocKind, value: string, found_in: string) => {
    if (evidence.length >= 80) return;
    const key = `${kind}\0${value}\0${found_in}`;
    if (!seenEvidence.has(key)) { seenEvidence.add(key); evidence.push({ kind, value, found_in }); }
    if (kind === "ip") ips.add(value);
    if (kind === "domain") domains.add(value);
    if (kind === "url") urls.add(value);
    if (kind === "md5") md5.add(value);
    if (kind === "sha256") sha256.add(value);
  };
  for (const { name, text } of sources.slice(0, 16)) {
    const sample = text.slice(0, 150000);
    for (const match of sample.matchAll(urlRegex)) {
      const original = match[0].replace(/[.,;!?]+$/, "");
      try {
        const parsed = new URL(original);
        if (parsed.username || parsed.password || !["http:", "https:"].includes(parsed.protocol)) continue;
        // Never fetch a URL from an untrusted report.
        add("url", original.slice(0, 500), name);
        if (isIP(parsed.hostname)) add("ip", parsed.hostname, name);
        else if (parsed.hostname.includes(".")) add("domain", parsed.hostname.toLowerCase(), name);
      } catch { /* malformed URL ignored */ }
    }
    for (const match of sample.matchAll(ipv4Regex)) {
      if (isIP(match[0])) add("ip", match[0], name);
    }
    for (const match of sample.matchAll(domainRegex)) {
      const val = match[0].toLowerCase();
      if (!isIP(val)) add("domain", val, name);
    }
    for (const match of sample.matchAll(hashRegex)) {
      const value = match[0].toLowerCase();
      add(value.length === 64 ? "sha256" : "md5", value, name);
    }
  }
  return { ips: [...ips].slice(0, 60), domains: [...domains].slice(0, 60),
    urls: [...urls].slice(0, 60), hashes_md5: [...md5].slice(0, 60),
    hashes_sha256: [...sha256].slice(0, 60), evidence };
}
