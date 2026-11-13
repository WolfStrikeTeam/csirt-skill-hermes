# Incident Intake MCP

**Status:** terintegrasi pada branch `feat/incident-intake`. Pengujian lokal lulus; integrasi Wazuh asli dan Hermes belum diuji.

Proyek ini dibuat sesuai FigJam dan `project-overview.md` terbaru: **Hermes (MCP Client) → MCP Server (`mcp-use`) → Wazuh**. Komponen Incident Intake **mencatat kandidat kasus**, tidak melakukan triage, enrichment IOC, rekomendasi respons, atau mengeksekusi aksi respons.

## Ruang lingkup

- Mendukung **Wazuh `alerts.json`** (input langsung) dan **Wazuh Indexer `_search`** (pull melalui API).
- Mendukung laporan `manual`/`email` **yang sudah diteruskan ke tool**. Tidak ada integrasi inbox/SMTP/IMAP otomatis.
- Normalisasi timestamp dan field Wazuh, validasi rule level 0–16, validasi alamat IP, batas ukuran input, sanitasi teks dasar, penghilangan `full_log` dan username dari output.
- ID kasus deterministik dan deduplikasi untuk alert Wazuh. Data disimpan sebagai JSON per kasus dengan exclusive-create (persisten saat proses direstart).
- Mengembalikan `IncidentCase` yang dapat dipakai tahap Triage. `rule_level` Wazuh **bukan** `severity` keputusan Hamza.
- Tidak menjalankan perintah pada server, tidak mengubah firewall, dan tidak membutuhkan API LLM.

## Struktur file

    hermes/
    ├── tools/incident-intake/mcp-tools.ts
    ├── services/incident-intake/
    │   ├── indexer.ts
    │   ├── normalize.ts
    │   ├── service.ts
    │   └── store.ts
    └── types/incident-intake.ts

    index.ts
    tests/incident-intake.test.mjs
    fixtures/
    tsconfig.intake.json
    docs/incident-intake/README.md

## Prasyarat

- Node.js **>= 22.22.2**, sesuai requirement repository tim.
- NPM dan dependencies project (`mcp-use@2.12.3`, `zod@^4.6.6`, TypeScript). Gunakan `npm ci` dari root repository tim.
- Untuk pengujian `intake_wazuh_alert` dari fixture, **tidak perlu Wazuh yang aktif**.

## Pengujian lokal

Jalankan dari root repository `csirt-skill-hermes`:

    npm ci
    npm run typecheck
    npm run test:intake
    npm run build
    npm run dev

Buka http://localhost:3000/mcp/inspector

Pada Inspector, jalankan tool **`intake_wazuh_alert`** dengan argument:

```json
{
  "source_id": "wazuh-local",
  "alert": {
    "timestamp": "2026-11-13T08:15:21.000+0000",
    "id": "1763021721.1091",
    "rule": {
      "id": "5712",
      "level": 10,
      "description": "Multiple SSH authentication failures detected",
      "groups": ["sshd"]
    },
    "agent": {"id": "001", "name": "ubuntu-lab"},
    "data": {"srcip": "198.51.100.23"}
  }
}
```

Pemanggilan pertama `status: "created"`, pemanggilan alert identik berikutnya `status: "existing"`. Periksa `case_id`, `status: "new"`, `classification_status: "pending"`, `wazuh.rule_level`, dan `observables.source_ip`. Gunakan `get_incident_case` untuk melihat lagi kasus tersebut.

## Integrasi MCP Server

Incident Intake sudah terdaftar pada `index.ts`.

Import yang digunakan:

    ./hermes/tools/incident-intake/mcp-tools.js

Registrasi:

    registerIncidentIntakeTools(server);

Modul menggunakan MCP Server bersama.
Jangan menghapus registrasi modul anggota tim lainnya.

Kontrak IncidentCase masih perlu direview bersama modul Triage.

## Lima MCP tools

| Tool | Input | Output / efek |
|---|---|---|
| `intake_wazuh_alert` | Alert JSON & `source_id` opsional | Membuat/mengembalikan kasus; idempotent |
| `collect_wazuh_alerts` | `since`, `min_rule_level`, `limit`, `offset` opsional | Baca page Wazuh Indexer dan catat kasus; lapor jumlah berhasil/ditolak |
| `intake_forwarded_report` | `channel` manual/email, title, description, reference opsional | Membuat kasus dari laporan yang diberikan klien |
| `get_incident_case` | `case_id` | Mengambil satu kasus untuk triage |
| `list_incident_cases` | `limit` opsional | Menampilkan kasus tanpa raw log |

## Tes dengan Wazuh asli (nanti setelah server Nopal aktif)

Akses yang dibutuhkan adalah **Wazuh Indexer REST API** (umumnya port `9200`), **bukan** Wazuh Manager API (umumnya port `55000`). Minta kredensial **read-only** untuk index `wazuh-alerts-*`.

Set environment dalam `.env` (jangan commit file ini):

```dotenv
HOST=127.0.0.1
INTAKE_DATA_DIR=./data/incident-intake
WAZUH_SOURCE_ID=lab-nopal
WAZUH_INDEXER_URL=https://HOST_INDEXER:9200/
WAZUH_INDEXER_USERNAME=READ_ONLY_USERNAME
WAZUH_INDEXER_PASSWORD=READ_ONLY_PASSWORD
```

Atau gunakan `WAZUH_INDEXER_TOKEN` sebagai pengganti username/password. `collect_wazuh_alerts` default mengambil page 50 alert terbaru dari 15 menit terakhir dengan minimum `rule.level >= 3`. Gunakan `since` ISO 8601 untuk waktu yang lebih lama dan `offset` sesuai `next_offset` bila perlu.

**TLS:** jangan pakai `NODE_TLS_REJECT_UNAUTHORIZED=0`. Jika Wazuh Indexer memakai CA internal, konfigurasi trust CA yang benar (misalnya `NODE_EXTRA_CA_CERTS=/path/ca.pem`). Hanya HTTP loopback yang diperbolehkan untuk unit test.

## Kontrak output ke Hamza

`fixtures/example-incident-case.json` memuat bentuk output lengkap yang saat ini dihasilkan Intake. Field utama:

```json
{
  "schema_version": "1.0",
  "case_id": "INC-...",
  "source": {"type": "wazuh", "instance": "wazuh-local", "external_id": "..."},
  "status": "new",
  "classification_status": "pending",
  "created_at": "2026-11-13T09:00:00.000Z",
  "occurred_at": "2026-11-13T08:15:21.000Z",
  "title": "Wazuh rule ...",
  "description": "...",
  "observables": {"source_ip": "198.51.100.23"},
  "wazuh": {"rule_id": "5712", "rule_level": 10, "groups": ["sshd"]}
}
```

**Kontrak ini sementara** dan harus disepakati Hamza/Nopal. Modul Intake sengaja **tidak mengisi** `severity`, `confidence`, `category`, ataupun `mitre_technique`, karena itu urusan Triage.

## Pertimbangan keamanan dan batasan MVP

- Teks `description` dan seluruh field turunan alert tetap **data tak tepercaya** bagi Hermes; normalisasi/redaksi dasar **bukan** perlindungan prompt-injection yang sempurna. Agent harus memisahkan data dari instruksi.
- Hanya field tertentu diambil dari Indexer; `full_log`, username, dan raw request tidak disalin ke kasus. Redaksi regex tidak menjamin penghilangan semua PII.
- Data kasus disimpan di file lokal JSON; default permission 0700/0600 pada POSIX. Tidak ada encryption-at-rest/retention policy atau akses multi-tenant dalam MVP.
- Pull memakai `from`+`size`, sortir timestamp descending. **Pagination tidak konsisten jika alert baru masuk saat berpindah halaman**; solusi produksi memerlukan PIT/search_after atau strategi cursor/watermark yang stabil.
- Batas 100 alert/request dan 10.000 offset. Untuk produksi ber-volume tinggi, perlu queue, checkpoint, retry, dan audit lebih kuat.
- Tidak ada auth pada endpoint MCP yang ditambahkan oleh modul ini. **Hanya jalankan di localhost untuk development**; deployment bersama harus menambahkan autentikasi/otorisasi pada server.
- Wazuh server asli dan klien Hermes belum diuji dalam artefak ini.

Referensi resmi:
- MCP use: https://docs.mcp-use.com/typescript/getting-started/welcome
- MCP tools: https://docs.mcp-use.com/typescript/server/tools
- Wazuh alert indices: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html
- Wazuh Indexer API use case: https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html
- Wazuh rule levels: https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html
