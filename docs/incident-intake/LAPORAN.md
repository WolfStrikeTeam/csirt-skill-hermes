# Laporan Pengembangan dan Pengujian Lokal — Incident Intake (MVP)

**Tanggal:** 13 November 2026
**PIC:** Dika — Incident Intake
**Status:** **LULUS pengujian lokal; diajukan untuk code review dan integrasi tim (belum production-ready)**
**Acuan kerja:** FigJam pembagian modul (Nopal), `project-overview.md` (Hamza), dan repo MCP server berbasis `mcp-use`. Nama produk sengaja tidak dijadikan acuan, sesuai kesepakatan.

## 1. Ringkasan untuk tim

Modul **Incident Intake** (tahap pertama workflow CSIRT) telah diimplementasikan dengan **TypeScript, Node.js, dan `mcp-use`**. Untuk MVP, modul bisa menerima **Wazuh alert JSON**, menormalisasi atribut dasar, mencatat kasus dengan ID stabil, mencegah duplikasi, menyimpan kasus lokal, dan menyediakan API berbentuk **MCP tools** untuk modul triage. Ada pula jalur laporan manual/email-forwarded yang menerima teks *yang diberikan klien*, **bukan** membaca inbox otomatis.

**Batas pekerjaan:** Intake **tidak** melakukan klasifikasi severity final, confidence, MITRE ATT&CK, investigasi IOC, maupun tindakan keamanan. Tanggung jawab tahapan itu tetap pada modul anggota tim lain. MCP server pada Project Overview hanya memberikan informasi dan rekomendasi, bukan mengeksekusi tindakan respons.

**Hasil:** pengujian otomatis **15/15 PASS**, `mcp-use typecheck` **0 error**, MCP Inspector berhasil mengakses server dan menjalankan **create, dedup, list, get**, serta kasus **bertahan setelah restart server**, berdasarkan bukti terminal/screenshot dan konfirmasi penguji di komputer lokal.

## 2. Alur data yang diuji

```text
Wazuh alert JSON (fixture lokal)
           │
           ▼
MCP tool: intake_wazuh_alert
           │
       Validate → Normalize → Deduplikasi
           │
           ▼
 IncidentCase v1 (penyimpanan JSON lokal)
           │
           ├── list_incident_cases
           └── get_incident_case
                       │
                       ▼
             Triage milik Hamza (belum terintegrasi)
```

**Jalur lain yang tersedia dalam kode, tetapi belum diuji ke sistem nyata:**

```text
Wazuh Indexer API (_search) → collect_wazuh_alerts → IncidentCase
Forwarded email/manual text → intake_forwarded_report → IncidentCase
```

## 3. Lima MCP tools yang tersedia

| Tool | Fungsi | Bukti verifikasi |
|---|---|---|
| `intake_wazuh_alert` | Membuat atau menggunakan kembali kasus dari satu Wazuh JSON | **PASS via MCP Inspector** (created/existing) |
| `collect_wazuh_alerts` | Query terbatas ke Wazuh Indexer API lalu mengingesti hasil | **PASS pada unit/integration test dengan HTTP mock**; **belum** diuji pada Wazuh asli |
| `intake_forwarded_report` | Membuat kasus dari teks laporan manual/email yang diteruskan | **PASS pada automated tests**; belum terhubung inbox |
| `get_incident_case` | Mencari detail kasus menurut `case_id` | **PASS via MCP Inspector** |
| `list_incident_cases` | Menampilkan kasus yang tersimpan | **PASS via MCP Inspector**, termasuk setelah restart |

## 4. Lingkungan dan hasil pengujian

**Lingkungan pengujian:** Kali Linux WSL, Node.js `v24.19.0`, npm `11.19.0`; server `mcp-use dev` di `http://localhost:3000/mcp`; Inspector di `http://localhost:3000/mcp/inspector`.

| Langkah | Hasil faktual | Status |
|---|---|---|
| `npm install` | Berhasil; log npm: 0 vulnerabilities saat pemasangan | PASS |
| `npm test` | 15 tests, 15 pass, 0 fail | PASS |
| `npm run typecheck` | `[mcp-use] no type errors (246ms)` | PASS |
| `npm run dev` | Server ready; `tools/list` HTTP 200; 5 tools tersedia | PASS |
| `intake_wazuh_alert` — pertama | `status: "created"` | PASS |
| `intake_wazuh_alert` — alert sama | `status: "existing"` (kasus tidak dibuat ulang) | PASS |
| `list_incident_cases` | `count: 1` untuk data tes | PASS |
| `get_incident_case` | `found: true` dengan `case_id` yang benar | PASS |
| Restart server lalu `list_incident_cases` | Kasus masih ada, **dikonfirmasi penguji** | PASS (konfirmasi pengguna; tanpa log terlampir) |

**Contoh data uji:**

| Field | Nilai |
|---|---|
| Sumber | `wazuh-local` |
| Wazuh rule ID | `5712` |
| Wazuh rule level | `10` (level bawaan Wazuh; **bukan severity final**) |
| Source IP | `198.51.100.23` (alamat uji) |
| Agent | `ubuntu-lab` |
| Case ID | `INC-27CA62E0D0A52608C9BA3EC1` |
| Case status | `new` |
| Classification status | `pending` |

**Catatan perbaikan kode:** paket awal menghasilkan **5 error `TS2345`** pada `incident-intake/mcp-tools.ts`, disebabkan helper `success()` melebarkan tipe `structuredContent` menjadi `Record<string, unknown>`. Helper diperbaiki untuk mempertahankan tipe output generik dan menyertakan `isError: false`. Setelah perbaikan di lingkungan penguji, `npm run typecheck` dan 15 tes semuanya berhasil. Versi paket review berisi perbaikan ini.

**Error input yang sempat muncul tetapi bukan bug:** tool `get_incident_case` sempat diberi angka `5712` (Wazuh **rule ID**), bukan `INC-...` (**case ID**). Setelah memakai case ID yang benar, respons `found: true`.

## 5. Kontrak output sementara untuk modul Triage

Contoh field penting (bukan seluruh struktur):

```json
{
  "schema_version": "1.0",
  "case_id": "INC-27CA62E0D0A52608C9BA3EC1",
  "source": {
    "type": "wazuh",
    "instance": "wazuh-local",
    "external_id": "1763021721.1091"
  },
  "status": "new",
  "classification_status": "pending",
  "occurred_at": "2026-11-13T08:15:21.000Z",
  "title": "Wazuh rule 5712: Multiple SSH authentication failures detected",
  "description": "Multiple SSH authentication failures detected",
  "observables": {
    "source_ip": "198.51.100.23"
  },
  "wazuh": {
    "rule_id": "5712",
    "rule_level": 10,
    "groups": ["sshd"],
    "agent": { "id": "001", "name": "ubuntu-lab" }
  }
}
```

**`created_at` juga ada pada respons asli**, tetapi sengaja dihilangkan dari contoh ringkas ini. Contoh lengkap terdapat di `fixtures/example-incident-case.json` pada paket source. Kontrak ini **masih perlu persetujuan Hamza**.

## 6. Pengamanan yang diterapkan dan batasannya

**Sudah ada pada implementasi MVP:** validasi input dan batas ukuran, pembatasan pagination, pembersihan/redaksi dasar field tertentu dari log, penyimpanan kasus tanpa menyalin `full_log`, deduplikasi berdasarkan identitas sumber, validasi format case ID, pembatasan komunikasi HTTP Indexer yang tidak aman, serta **tidak ada kode yang mengeksekusi respons keamanan**.

**Belum dapat diklaim aman untuk produksi:** redaksi field bukan jaminan menyaring semua PII atau prompt injection; file JSON lokal belum memiliki enkripsi-at-rest, retensi, audit access, dan model multi-user; server MCP yang dibuka ke jaringan membutuhkan autentikasi/otorisasi; akses Indexer asli beserta TLS/CA belum diverifikasi; pagination `from`/`size` dapat berubah ketika alert terus masuk dan membutuhkan mekanisme cursor/checkpoint untuk layanan berkelanjutan.

## 7. Hal yang masih pending dan perlu keputusan tim

**Nopal (Wazuh/integrasi):**
- Menentukan kapan Wazuh server/Indexer dinyalakan untuk uji end-to-end.
- Konfirmasi **Indexer API** dan akses **read-only** ke `wazuh-alerts-*`, termasuk URL, hak akses, dan sertifikat CA internal jika diperlukan; jangan membagikan kredensial ke chat/repo.
- Menentukan kebutuhan **pull on-demand** (implementasi saat ini) versus webhook/push untuk alert real-time.

**Hamza (handoff Triage):**
- Meninjau `IncidentCase` v1 (`schema_version`, `case_id`, `source`, `occurred_at`, `observables`, `wazuh`).
- Menentukan kebutuhan field tambahan atau adapter bila modul Triage mempunyai kontrak yang berbeda.
- Menyetujui batas pengubahan alert menjadi kasus. Saat ini alert yang diterima tool akan dicatat; pengambilan melalui Indexer memiliki filter minimal Wazuh rule level.

**Tim/integrasi:**
- Memastikan modul didaftarkan satu kali di `index.ts` server tim; **jangan mengganti entrypoint milik anggota lain**.
- Menguji pemanggilan oleh **Hermes Agent** dan menguji pada repository gabungan.
- Membahas storage, keamanan akses MCP, dan batas deployment.

## 8. Status kesiapan dan saran next step

**Siap:** review kode dan presentasi demo lokal, serta uji integrasi antar-modul di lingkungan development.
**Belum siap:** klaim live Wazuh integration, Hermes end-to-end, continuous ingestion, dan production deployment.

**Urutan yang disarankan sebelum push/merge:** (1) kirim laporan dan demo ke Nopal & Hamza; (2) minta review kontrak dan sumber Indexer; (3) integrasikan file `incident-intake/` tanpa menimpa `index.ts` existing; (4) jalankan tes pada repo gabungan; (5) tes koneksi Wazuh asli setelah tersedia; (6) lanjutkan pull request untuk review.

## 9. Lampiran bukti

- Hasil terminal dari pengguna: `npm install`, `npm test` (15/15), `npm run typecheck` (0 error), `npm run dev` dan `tools/list` sukses.
- Screenshot MCP Inspector yang dibagikan pengguna: `created`, `list` (`count: 1`), `existing` pada alert yang sama, dan `get` (`found: true`).
- Konfirmasi eksplisit pengguna bahwa kasus tetap ada setelah restart MCP Server.
- Sumber kode dan fixture: paket **Incident Intake MCP Review v1.1**.

**Kesimpulan:** Modul Incident Intake **berfungsi untuk workflow dasar lokal** sesuai tanggung jawab Modul 1; review tim dan pengujian integrasi nyata diperlukan sebelum push ke repo bersama/production.
