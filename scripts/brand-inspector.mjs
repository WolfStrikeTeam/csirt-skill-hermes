#!/usr/bin/env node
/**
 * Replace the hardcoded "mcp-use Inspector" header logo in @mcp-use/inspector
 * with WOLFSTRIKE branding (branding/inspector.json + its logo file).
 *
 * The inspector exposes no branding option, so this patches the installed
 * bundle. Originals are kept as *.wolfstrike-orig and every run patches from
 * them, so editing the logo and re-running is safe. If the upstream bundle
 * changes shape, the script warns and leaves the file untouched; it never
 * fails `npm install`.
 *
 * Usage: node scripts/brand-inspector.mjs [--restore]
 */
import { readFileSync, writeFileSync, existsSync, copyFileSync } from "node:fs";
import { gzipSync, gunzipSync } from "node:zlib";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ORIG = ".wolfstrike-orig";
const warn = (msg) => console.warn(`[brand-inspector] ${msg}`);
const log = (msg) => console.log(`[brand-inspector] ${msg}`);

function inspectorDist() {
  try {
    const require = createRequire(path.join(root, "package.json"));
    const pkg = require.resolve("@mcp-use/inspector/package.json", {
      paths: [root, path.join(root, "node_modules/@mcp-use/cli")],
    });
    return path.join(path.dirname(pkg), "dist");
  } catch {
    // Not exported as a subpath; fall back to the hoisted location.
    const p = path.join(root, "node_modules/@mcp-use/inspector/dist");
    return existsSync(p) ? p : null;
  }
}

/** Return the original file contents, saving a backup on first run. */
function original(file) {
  const backup = file + ORIG;
  if (!existsSync(backup)) copyFileSync(file, backup);
  return readFileSync(backup);
}

function loadBranding() {
  const cfgPath = path.join(root, "branding/inspector.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  const logoPath = path.join(root, "branding", cfg.logo);
  const ext = path.extname(logoPath).toLowerCase();
  const mime = { ".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp", ".jpg": "image/jpeg", ".jpeg": "image/jpeg" }[ext];
  if (!mime) throw new Error(`unsupported logo type: ${ext}`);
  const logo = `data:${mime};base64,${readFileSync(logoPath).toString("base64")}`;
  return { name: cfg.name, pageTitle: cfg.pageTitle, logo };
}

/** Swap the animated SVG mark and the "mcp-use" wordmark inside the Logo component. */
function patchBundle(src, { name, logo }) {
  const start = src.indexOf('labelParts: i = "full"');
  if (start < 0) return null;
  const fnStart = src.lastIndexOf("function ", start);
  const fnEnd = src.indexOf("\nfunction ", start);
  if (fnStart < 0 || fnEnd < 0) return null;
  let fn = src.slice(fnStart, fnEnd);

  // `, m = jsx("div", { className: "relative", children: <animated svg> }), h = r ? ...`
  const markRe = /, (\w+) = \/\* @__PURE__ \*\/ \(0, (\w+)\.jsx\)\("div", \{\s*className: "relative",[\s\S]*?style: \{\s*width: (\w+),[\s\S]*?\n\t\}\), (\w+) = (\w+) \? /;
  const m = fn.match(markRe);
  if (!m) return null;
  const [, markVar, jsxNs, sizeVar, labelVar, showVar] = m;
  const img =
    `, ${markVar} = (0, ${jsxNs}.jsx)("img", { src: ${JSON.stringify(logo)}, alt: ${JSON.stringify(name)}, ` +
    `draggable: false, className: "shrink-0 object-contain", style: { width: "auto", height: ${sizeVar} } }), ` +
    `${labelVar} = ${showVar} ? `;
  fn = fn.replace(markRe, () => img);

  const word = 'children: "mcp-use"';
  if (!fn.includes(word)) return null;
  fn = fn.replace(word, `children: ${JSON.stringify(name)}`);

  return src.slice(0, fnStart) + fn + src.slice(fnEnd);
}

function main() {
  const dist = inspectorDist();
  if (!dist) return warn("@mcp-use/inspector not installed; skipping.");
  const bundle = path.join(dist, "app/inspector.js.gz");
  const server = path.join(dist, "server/index.js");

  if (process.argv.includes("--restore")) {
    for (const f of [bundle, server]) if (existsSync(f + ORIG)) copyFileSync(f + ORIG, f);
    return log("restored original mcp-use branding.");
  }

  const branding = loadBranding();

  const patched = patchBundle(gunzipSync(original(bundle)).toString("utf8"), branding);
  if (!patched) return warn("logo component not found (inspector version changed?); bundle left as-is.");
  writeFileSync(bundle, gzipSync(patched, { level: 9 }));

  const title = "<title>Inspector | mcp-use</title>";
  const serverSrc = original(server).toString("utf8");
  if (branding.pageTitle && serverSrc.includes(title)) {
    writeFileSync(server, serverSrc.replace(title, `<title>${branding.pageTitle}</title>`));
  } else {
    writeFileSync(server, serverSrc);
  }

  log(`Inspector branded as "${branding.name}". Restart \`npm run dev\` to see it.`);
}

try {
  main();
} catch (err) {
  warn(`skipped: ${err.message}`);
}
