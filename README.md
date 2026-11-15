# WOLFSTRIKE

MCP server untuk penanganan insiden keamanan. Dipanggil oleh AI agent (Hermes, OpenClaw, atau AI coding agent) lewat MCP. Dibangun dengan TypeScript, Node.js, dan [mcp-use](https://mcp-use.com/docs/typescript/getting-started/quickstart).

```
Hermes (agent) --MCP--> WOLFSTRIKE ---> Wazuh, TheHive, VirusTotal, Email, dll
```

## Modul MVP

Output satu modul jadi input modul berikutnya.

| # | Modul | Output |
|---|---|---|
| 1 | Incident Intake | Case insiden |
| 2 | Triage & Classification | Category, severity, confidence, prioritas, MITRE ATT&CK, Cyber Kill Chain |
| 3 | MITRE ATT&CK Mapping | Tactic, technique, sub-technique |
| 4 | Threat Investigation & IOC Enrichment | IOC (IP, SHA-256, MD5, domain), evidence, findings |
| 5 | Reporting & Response | Incident report, action plan, block IP/IOC |

Batas otomatisasi: block IP/IOC adalah satu-satunya aksi yang dieksekusi. Selain itu hanya rekomendasi.

## Development

Butuh Node.js `>=22.22.2`.

```bash
npm install
npm run dev
```

- MCP endpoint: http://localhost:3000/mcp
- Inspector (buat ngetes tool): http://localhost:3000/mcp/inspector

Server auto-reload tiap file diubah. Tool didaftarkan di `index.ts`.

| Script | Fungsi |
|---|---|
| `npm run dev` | Dev server + inspector |
| `npm run typecheck` | Refresh type MCP dan cek TypeScript |
| `npm run build` | Build production |
| `npm run start` | Jalankan hasil build |
| `npm run update-tlds` | Perbarui daftar TLD IANA (`hermes/services/tlds.ts`) |

## Konfigurasi

| Env | Fungsi |
|---|---|
| `VT_API_KEY` | API key VirusTotal untuk `validate_iocs`, `enrich_ioc`, `investigate_incident` |
| `WOLFSTRIKE_EXTRA_TLDS` | Suffix tambahan yang dihitung sebagai domain, pisah koma. Contoh: `newtld,acme` |
| `WOLFSTRIKE_TLD_CHECK` | Isi `off` supaya semua token bertitik dianggap domain (tanpa cek TLD) |

`extract_iocs` hanya menganggap token sebagai domain kalau akhirannya TLD resmi IANA, atau suffix khusus: `.onion`, `.i2p`, `.bit`, suffix jaringan internal (`.internal`, `.local`, `.corp`, dll.), dan `.test`/`.localhost`/`.example`. Jadi nama file (`payload.exe`) dan potongan kode (`http.server`) tidak ikut terbaca sebagai domain. Daftar TLD diperbarui otomatis tiap minggu lewat GitHub Action `update-tlds`, yang membuka PR kalau IANA merilis versi baru.

## Lisensi

MIT
