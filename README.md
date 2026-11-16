# WOLFSTRIKE

### MCP server untuk penanganan insiden keamanan, dipanggil langsung dari AI agent.

**Kasih alert ke agent, dapat IOC, temuan, dan laporan insiden yang bisa dipertanggungjawabkan.**

[![Node.js](https://img.shields.io/badge/node-%3E%3D22.22.2-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-server-6E56CF)](https://modelcontextprotocol.io/)
[![mcp-use](https://img.shields.io/badge/built%20with-mcp--use-111111)](https://mcp-use.com/docs/typescript/getting-started/quickstart)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

[Quick start](#quick-start) · [Cara kerja](#cara-kerja) · [Tool MCP](#tool-mcp) · [Contoh kasus](#contoh-kasus) · [Konfigurasi](#konfigurasi) · [Development](#development) · [FAQ](#faq)

---

WOLFSTRIKE adalah MCP server untuk tim CSIRT. Server ini tidak jalan sendiri: yang memanggilnya adalah AI agent seperti [Hermes](https://hermes-agent.nousresearch.com/docs), OpenClaw, atau AI coding agent lain yang mendukung MCP. Agent membaca alert, memanggil tool WOLFSTRIKE untuk mengekstrak dan memvalidasi IOC, lalu menyusun laporan insiden.

```
Hermes (agent) --MCP--> WOLFSTRIKE ---> Wazuh, TheHive, VirusTotal, Email, dll
```

Dibangun dengan TypeScript, Node.js, dan [mcp-use](https://mcp-use.com/docs/typescript/getting-started/quickstart).

> [!IMPORTANT]
> **Batas otomatisasi:** block IP/IOC adalah satu-satunya aksi yang dieksekusi, dan itu pun hanya kalau `executeBlock: true` dikirim secara eksplisit. Selain itu semua output adalah rekomendasi. Keputusan akhir tetap di tangan analis.

## Quick start

### 1. Jalankan server

Butuh Node.js `>=22.22.2`.

```bash
npm install
npm run dev
```

- MCP endpoint: http://localhost:3000/mcp
- Inspector (buat ngetes tool tanpa agent): http://localhost:3000/mcp/inspector

### 2. Hubungkan ke Hermes

Tambahkan WOLFSTRIKE ke `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  wolfstrike:
    url: "http://localhost:3000/mcp"
```

Persona analis CSIRT (`SOUL.md`), skill tim, dan koneksi TheHive dijelaskan lengkap di [hermes/README.md](hermes/README.md). Contoh config ada di [hermes/config.example.yaml](hermes/config.example.yaml).

### 3. Tanya agent

Setelah `/reload-mcp` di sesi Hermes, langsung minta dalam bahasa biasa:

    Investigasi log access Apache ini. Daftar semua IP yang mencurigakan,
    validasi IOC-nya, dan kasih severity berdasarkan bukti.

Hermes memilih skill [`incident-intake`](hermes/skills/incident-intake/SKILL.md), [`threat-investigation`](hermes/skills/threat-investigation/SKILL.md), atau [`incident-summary`](hermes/skills/incident-summary/SKILL.md) sendiri, lalu memanggil tool WOLFSTRIKE sesuai kebutuhan.

## Cara kerja

WOLFSTRIKE dibagi jadi lima modul. Output satu modul jadi input modul berikutnya.

```
1. Intake  -->  2. Triage  -->  3. MITRE ATT&CK  -->  4. Investigation  -->  5. Reporting
   (case)       (severity)      (TTP)                 (IOC + evidence)       (laporan + block)
```

| # | Modul | Output |
|---|---|---|
| 1 | Incident Intake | Case insiden yang sudah dinormalisasi + kandidat IOC, dari Wazuh, Gmail, TheHive, atau input manual |
| 2 | Triage & Classification | Category, severity, confidence, prioritas, MITRE ATT&CK, Cyber Kill Chain |
| 3 | MITRE ATT&CK Mapping | Tactic, technique, sub-technique |
| 4 | Threat Investigation & IOC Enrichment | IOC (IP, SHA-256, MD5, domain, URL), evidence, findings |
| 5 | Reporting & Response | Incident report, action plan, block IP/IOC |

## Tool MCP

Tool modul 2–5 didaftarkan di [`index.ts`](index.ts). Tool intake (Wazuh, Gmail, laporan manual) ada di [`hermes/tools/incident-intake/mcp-tools.ts`](hermes/tools/incident-intake/mcp-tools.ts). Case hasil intake disimpan lokal di `data/incident-intake/` dan `case_id`-nya dipakai sebagai kunci serah-terima ke modul berikutnya.

| Tool | Modul | Fungsi | Butuh | Status |
|---|---|---|---|---|
| `intake_incident` | 1 | Normalisasi alert dari Wazuh, TheHive, atau input manual, sekaligus ekstrak IOC awal | – | ✅ Jalan |
| `intake_wazuh_alert` | 1 | Buat case dari satu alert JSON Wazuh, atau pakai case yang sudah ada | – | ✅ Jalan |
| `collect_wazuh_alerts` | 1 | Tarik satu halaman alert dari Wazuh Indexer dan buat case secara idempoten | `WAZUH_INDEXER_*` | ✅ Jalan |
| `intake_forwarded_report` | 1 | Buat case dari teks laporan atau email yang di-forward manual | – | ✅ Jalan |
| `pull_csirt_gmail_reports` | 1 | Tarik laporan dari mailbox Gmail CSIRT (read-only), baca lampiran yang diizinkan, ekstrak kandidat IOC | `GMAIL_*` | ✅ Jalan |
| `get_incident_case` | 1 | Baca satu case yang sudah tercatat, buat diteruskan ke modul berikutnya | – | ✅ Jalan |
| `list_incident_cases` | 1 | Daftar ringkasan case yang sudah tercatat | – | ✅ Jalan |
| `triage_incident` | 2 | Klasifikasi severity, kemungkinan false positive, fase Kill Chain | – | ✅ Jalan |
| `map_mitre_attack` | 3 | Petakan perilaku atau log ke tactic dan technique MITRE ATT&CK | – | ✅ Jalan |
| `investigate_incident` | 4 | Alur lengkap: extract → validate → enrich IOC | `VT_API_KEY` | ✅ Jalan |
| `extract_iocs` | 4 | Ekstrak dan dedup IOC dari teks insiden dan evidence | – | ✅ Jalan |
| `validate_iocs` | 4 | Validasi maks. 20 IP, domain, URL, atau hash lewat lookup pasif VirusTotal | `VT_API_KEY` | ✅ Jalan |
| `enrich_ioc` | 4 | Ambil atribut tambahan satu IOC dari VirusTotal | `VT_API_KEY` | ✅ Jalan |
| `respond_and_report` | 5 | Susun laporan insiden dan catat aksi block IOC | – | ✅ Jalan |

Catatan status:

- **`triage_incident` dan `map_mitre_attack`** sengaja mengembalikan `status: "not-implemented"` tanpa nilai apa pun. Versi awalnya selalu mengembalikan hasil karangan (misalnya T1059 untuk semua input), dan agent membacanya sebagai konfirmasi. Detailnya ada di [docs/testing/INC-001.md](docs/testing/INC-001.md).
- **`respond_and_report`** sudah menyusun laporan, tapi block IOC belum tersambung ke firewall, Wazuh Active Response, atau EDR. Untuk sekarang aksi block hanya dicatat di laporan.

## Contoh kasus

Dua insiden nyata dipakai untuk menguji Hermes + WOLFSTRIKE dari awal sampai akhir.

### INC-001: Recon ke server WordPress

Dua host internal memindai server WordPress dengan WPScan, enumerasi username, dan probe SQL injection. Tidak ada bukti server dibobol, jadi severity **Medium**. Tes ini mengecek apakah agent bisa menahan diri dan tidak mengarang kompromi.

**[Baca laporan insiden](docs/incidents/INC-001.md)** · **[Baca laporan tes](docs/testing/INC-001.md)**

### INC-002: SSH brute force sampai root

Host internal melakukan brute force SSH, berhasil login, naik ke root lewat `sudo`, lalu mengambil `/etc/shadow` dan arsip aplikasi FileRun. Severity **Critical**.

**[Baca laporan insiden](docs/incidents/INC-002.md)** · **[Baca laporan tes](docs/testing/INC-002.md)**

## Konfigurasi

| Env | Fungsi |
|---|---|
| `VT_API_KEY` | API key VirusTotal untuk `validate_iocs`, `enrich_ioc`, `investigate_incident` |
| `VT_BASE_URL` | Base URL API VirusTotal. Default `https://www.virustotal.com/api/v3` |
| `VT_TIMEOUT_MS` | Timeout request ke VirusTotal dalam milidetik. Default `15000` |
| `WOLFSTRIKE_EXTRA_TLDS` | Suffix tambahan yang dihitung sebagai domain, pisah koma. Contoh: `newtld,acme` |
| `WOLFSTRIKE_TLD_CHECK` | Isi `off` supaya semua token bertitik dianggap domain (tanpa cek TLD) |
| `INTAKE_DATA_DIR` | Folder penyimpanan case hasil intake. Default `data/incident-intake` |
| `WAZUH_INDEXER_URL` | URL Wazuh Indexer untuk `collect_wazuh_alerts` |
| `WAZUH_INDEXER_TOKEN` | Token Wazuh Indexer. Alternatifnya `WAZUH_INDEXER_USERNAME` + `WAZUH_INDEXER_PASSWORD` |
| `WAZUH_SOURCE_ID` | Label cluster Wazuh. Default `wazuh-local` |
| `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, `GMAIL_REFRESH_TOKEN` | Kredensial OAuth Gmail untuk `pull_csirt_gmail_reports` |
| `GMAIL_QUERY` | Filter mailbox, wajib diisi (maks. 250 karakter). Contoh: `label:CSIRT` |
| `GMAIL_MAILBOX_ID` | Label mailbox di case. Default `csirt-gmail` |

Cara bikin kredensial Gmail (Google Cloud, OAuth, scope `gmail.readonly`, dan script [`scripts/setup-gmail-oauth.py`](scripts/setup-gmail-oauth.py)) ada di [GMAIL_SETUP.md](hermes/skills/incident-intake/GMAIL_SETUP.md). Jangan commit kredensial OAuth ke repo.

### Deteksi domain

`extract_iocs` hanya menganggap token sebagai domain kalau akhirannya TLD resmi IANA, atau salah satu suffix khusus berikut:

- `.onion`, `.i2p`, `.bit`
- suffix jaringan internal (`.internal`, `.local`, `.corp`, dll.)
- `.test`, `.localhost`, `.example`

Jadi nama file (`payload.exe`) dan potongan kode (`http.server`) tidak ikut terbaca sebagai domain. Daftar TLD diperbarui otomatis tiap minggu lewat GitHub Action [`update-tlds`](.github/workflows/update-tlds.yml), yang membuka PR kalau IANA merilis versi baru.

## Development

Server auto-reload tiap file diubah.

| Script | Fungsi |
|---|---|
| `npm run dev` | Dev server + inspector |
| `npm run typecheck` | Refresh type MCP dan cek TypeScript |
| `npm run build` | Build production |
| `npm run start` | Jalankan hasil build |
| `npm run update-tlds` | Perbarui daftar TLD IANA (`hermes/services/tlds.ts`) |
| `npm run test:intake` | Tes modul intake (Wazuh + Gmail) pakai fixture dan mock lokal |

Struktur folder:

```
.
├── index.ts                 # entry point: semua tool MCP didaftarkan di sini
├── hermes/
│   ├── SOUL.md              # persona Hermes sebagai analis CSIRT
│   ├── config.example.yaml  # contoh config Hermes (WOLFSTRIKE + TheHive)
│   ├── skills/              # skill Hermes: incident-intake, incident-summary, threat-investigation
│   ├── services/            # ekstraksi IOC, intake Wazuh/Gmail, investigasi
│   ├── tools/               # tool intake MCP + client VirusTotal
│   └── types/               # tipe data insiden
├── docs/
│   ├── incidents/           # laporan insiden
│   └── testing/             # laporan tes end-to-end
├── scripts/                 # updater TLD IANA, setup OAuth Gmail
└── tests/                   # tes intake + fixture alert Wazuh
```

## FAQ

**Kenapa cuma block IP/IOC yang otomatis?**
Block IP gampang dibatalkan dan dampaknya terbatas. Aksi lain seperti isolasi host, reset password, atau menutup case butuh konteks bisnis yang tidak dimiliki agent, jadi tetap diserahkan ke analis.

**Bisa jalan tanpa VirusTotal?**
Bisa. `intake_incident` dan `extract_iocs` tidak butuh API key. Tool yang butuh VirusTotal akan gagal karena request-nya ditolak VirusTotal, dan agent tetap bisa menganalisa dari log saja. Kedua tes di [docs/testing](docs/testing) dijalankan tanpa VirusTotal.

**Kenapa `payload.exe` tidak terbaca sebagai domain?**
Karena `.exe` bukan TLD. Lihat [Deteksi domain](#deteksi-domain). Kalau jaringanmu memakai suffix sendiri, tambahkan lewat `WOLFSTRIKE_EXTRA_TLDS`.

**Agent selain Hermes bisa pakai?**
Bisa. WOLFSTRIKE adalah MCP server biasa, jadi agent apa pun yang mendukung MCP over HTTP bisa terhubung ke `http://localhost:3000/mcp`. Persona dan skill di folder `hermes/` khusus untuk Hermes.

## Disclaimer

WOLFSTRIKE membantu analisa, bukan menggantikan analis. Output tool dan kesimpulan agent bisa salah, termasuk severity dan ID MITRE ATT&CK. Verifikasi setiap temuan terhadap bukti asli sebelum mengambil tindakan, dan pakai hanya pada sistem yang kamu berwenang tangani.

## Kontribusi

- Kerjakan di branch sendiri, jangan langsung ke `main`.
- Format commit: `type(scope): ringkasan`, contoh `fix(mcp): return not-implemented from triage placeholder`.
- Laporan bug dan ide fitur lewat [issues](https://github.com/Kartika-Cybersex/csirt-skill-hermes/issues). Perubahan kode lewat [pull request](https://github.com/Kartika-Cybersex/csirt-skill-hermes/pulls).

## Lisensi

[GNU General Public License v3.0](LICENSE).
