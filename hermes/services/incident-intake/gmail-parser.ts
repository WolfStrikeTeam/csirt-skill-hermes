/** Safe, bounded MIME parsing; no remote assets or HTML/attachment execution. */
import type { GmailApi, GmailMessage, GmailPart } from "./gmail-client.js";

const MAX_BODY_BYTES = 256 * 1024;
const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024;
const MAX_ATTACHMENTS = 6;

export interface TextSource { name: string; text: string }
export interface AttachmentStatus { name: string; status: "processed" | "skipped"; reason?: string }
export interface ParsedGmailReport {
  gmail_id: string;
  thread_id?: string;
  subject: string;
  sender: string;
  occurred_at: string;
  sources: TextSource[];
  attachments: AttachmentStatus[];
}

function clean(value: string, max: number): string {
  return value.replace(/[\x00-\x1f\x7f-\x9f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}
export function decodeBase64Url(value: string, maxBytes: number): Buffer {
  if (typeof value !== "string" || !/^[a-zA-Z0-9_\-]*={0,2}$/.test(value)) {
    throw new Error("Gmail base64url tidak valid");
  }
  if (value.length > Math.ceil(maxBytes / 3) * 4 + 8) throw new Error("Lampiran terlalu besar");
  const data = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (data.byteLength > maxBytes) throw new Error("Lampiran terlalu besar");
  return data;
}
function header(part: GmailPart, name: string): string {
  return part.headers?.find(h => h.name?.toLowerCase() === name.toLowerCase())?.value ?? "";
}
function decodeHeader(value: string): string {
  return value.replace(/=\?([^?]+)\?([bq])\?([^?]+)\?=/gi, (_all, cs: string, enc: string, text: string) => {
    try {
      const buf = enc.toLowerCase() === "b" ? Buffer.from(text, "base64")
        : Buffer.from(text.replace(/_/g, " ").replace(/=([a-f\d]{2})/gi, (_s: string, hex: string) => String.fromCharCode(parseInt(hex, 16))), "binary");
      return new TextDecoder(cs).decode(buf);
    } catch { return "[unsupported-header-encoding]"; }
  });
}
function getCharset(part: GmailPart): string {
  const ct = header(part, "Content-Type");
  return ct.match(/charset\s*=\s*["']?([\w-]+)/i)?.[1] ?? "utf-8";
}
function decodeText(part: GmailPart): string {
  if (!part.body?.data) return "";
  const raw = decodeBase64Url(part.body.data, MAX_BODY_BYTES);
  let text: string;
  try { text = new TextDecoder(getCharset(part), { fatal: false }).decode(raw); }
  catch { text = raw.toString("utf8"); }
  return text.slice(0, 120000);
}
function htmlToText(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<\s*(script|style|iframe|object|svg)\b[^>]*>[\s\S]*?<\/\s*\1\s*>/gi, " ")
    .replace(/<\s*br\b[^>]*\/?>/gi, "\n")
    .replace(/<\/\s*(p|div|li|tr|h[1-6])\s*>/gi, "\n")
    .replace(/<[^>]*>/g, " ")
    .replace(/&(?:amp|lt|gt|quot|apos|nbsp|#39);/gi, code => ({
      "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"',
      "&apos;": "'", "&nbsp;": " ", "&#39;": "'",
    }[code.toLowerCase()] ?? " "))
    .slice(0, 120000);
}
function flatten(part: GmailPart, depth = 0, output: GmailPart[] = []): GmailPart[] {
  if (depth > 8 || output.length >= 60) return output;
  output.push(part);
  for (const child of part.parts ?? []) {
    if (!child || typeof child !== "object" || output.length >= 60) break;
    flatten(child, depth + 1, output);
  }
  return output;
}

/** Optional parser packages are installed by the user; failures are explicitly recorded. */
export async function parseAttachmentText(filename: string, mime: string, data: Buffer): Promise<string> {
  const ext = filename.toLowerCase().split(".").pop();
  if (data.byteLength > MAX_ATTACHMENT_BYTES) throw new Error("file-size-limit");
  if (ext === "txt" && ["text/plain", "application/octet-stream", ""].includes(mime)) {
    return data.toString("utf8").slice(0, 100000);
  }
  if (ext === "pdf" && ["application/pdf", "application/octet-stream"].includes(mime)) {
    if (!data.subarray(0, 5).equals(Buffer.from("%PDF-"))) throw new Error("invalid-pdf-signature");
    // Use a variable import path to allow the core/MCP code to typecheck without optional package installed.
    const moduleName = "pdfjs-dist/legacy/build/pdf.mjs";
    const pdfjs = await import(/* @vite-ignore */ moduleName) as { getDocument: (args: unknown) => { promise: Promise<any>; destroy: () => Promise<void> } };
    const docTask = pdfjs.getDocument({ data: new Uint8Array(data), useSystemFonts: true, disableFontFace: true });
    const pdf = await docTask.promise;
    try {
      const count = Math.min(pdf.numPages, 15);
      const chunks: string[] = [];
      for (let i = 1; i <= count; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        chunks.push(content.items.map((item: { str?: string }) => item.str ?? "").join(" "));
        if (chunks.join(" ").length >= 100000) break;
      }
      return chunks.join("\n").slice(0, 100000);
    } finally { await docTask.destroy(); }
  }
  if (ext === "docx" && ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/octet-stream"].includes(mime)) {
    if (data[0] !== 0x50 || data[1] !== 0x4b) throw new Error("invalid-docx-signature");
    const moduleName = "mammoth";
    const mammoth = await import(/* @vite-ignore */ moduleName) as { extractRawText: (opt: { buffer: Buffer }) => Promise<{ value: string }> };
    const result = await mammoth.extractRawText({ buffer: data });
    return result.value.slice(0, 100000);
  }
  throw new Error("unsupported-attachment-type");
}

export async function parseGmailReport(message: GmailMessage, client: GmailApi): Promise<ParsedGmailReport> {
  if (!message.payload || !message.id) throw new Error("Pesan Gmail tidak memiliki payload");
  const parts = flatten(message.payload);
  const subject = clean(decodeHeader(header(message.payload, "Subject")) || "Untitled CSIRT report", 200);
  // Redact reporter email to minimize personal data stored in MVP.
  const sender = clean(header(message.payload, "From"), 150).replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi, "[REDACTED-EMAIL]");
  let time = new Date().toISOString();
  if (message.internalDate && /^\d{10,16}$/.test(message.internalDate)) {
    const ms = Number(message.internalDate);
    if (Number.isFinite(ms) && ms > 0 && ms < 8640000000000000) time = new Date(ms).toISOString();
  }
  const plain = parts.filter(p => !p.filename && p.mimeType === "text/plain" && p.body?.data);
  const html = parts.filter(p => !p.filename && p.mimeType === "text/html" && p.body?.data);
  const bodySources = (plain.length ? plain : html).slice(0, 8).map(p => ({
    name: "body", text: p.mimeType === "text/html" ? htmlToText(decodeText(p)) : decodeText(p),
  }));
  const sources: TextSource[] = [{ name: "subject", text: subject }, ...bodySources];
  const attachmentParts = parts.filter(p => typeof p.filename === "string" && p.filename.length > 0);
  const attachments: AttachmentStatus[] = [];
  for (const [index, part] of attachmentParts.entries()) {
    const name = clean(part.filename ?? "unknown", 96).replace(/[\\/]/g, "_");
    if (index >= MAX_ATTACHMENTS) { attachments.push({ name, status: "skipped", reason: "attachment-count-limit" }); continue; }
    const ext = name.toLowerCase().split(".").pop();
    if (!["txt", "pdf", "docx"].includes(ext ?? "")) {
      attachments.push({ name, status: "skipped", reason: "unsupported-attachment-type" }); continue;
    }
    if ((part.body?.size ?? 0) > MAX_ATTACHMENT_BYTES) {
      attachments.push({ name, status: "skipped", reason: "attachment-size-limit" }); continue;
    }
    try {
      const encoded = part.body?.data ?? (part.body?.attachmentId
        ? (await client.attachment(message.id, part.body.attachmentId)).data : undefined);
      if (typeof encoded !== "string") throw new Error("attachment-data-missing");
      const raw = decodeBase64Url(encoded, MAX_ATTACHMENT_BYTES);
      const extracted = await parseAttachmentText(name, part.mimeType ?? "", raw);
      if (!extracted.trim()) throw new Error("no-extractable-text");
      sources.push({ name: `attachment:${name}`, text: extracted });
      attachments.push({ name, status: "processed" });
    } catch (error) {
      // Never return error details from document/parser dependencies; could include sensitive data.
      const reason = error instanceof Error && ["unsupported-attachment-type", "invalid-pdf-signature", "invalid-docx-signature", "no-extractable-text", "attachment-data-missing", "Lampiran terlalu besar"].includes(error.message)
        ? error.message : "attachment-read-or-parser-failed";
      attachments.push({ name, status: "skipped", reason });
    }
  }
  return { gmail_id: message.id, ...(message.threadId ? { thread_id: message.threadId } : {}),
    subject, sender, occurred_at: time, sources, attachments };
}
