# Panduan Gmail OAuth untuk Incident Intake (Hermes CSIRT)

Panduan ini untuk **developer/operator MCP Server CSIRT**, bukan setiap pengguna Hermes. Satu MCP Server yang terhubung ke satu mailbox CSIRT dapat dipakai oleh beberapa Hermes client **apabila** server dideploy dengan autentikasi, HTTPS, dan kontrol akses yang memadai.

> **Status implementasi:** berdasarkan hasil pengujian pengembang, pembacaan Gmail asli, body, PDF digital, TXT, ekstraksi IOC kandidat, dan pembuatan Incident Case berhasil diuji secara lokal menggunakan Hermes pada 15 November 2026. Wazuh asli, DOCX asli, orkestrasi triage/investigation, dan deployment multiuser **belum dinyatakan teruji**. Tidak ada pemblokiran otomatis oleh Incident Intake.

## 1. Cara kerja

```text
Analis di Hermes
    ↓ panggil pull_csirt_gmail_reports(limit 1–10)
MCP Server CSIRT (Node.js + TypeScript, HTTP)
    ↓ Gmail API, OAuth 2.0 gmail.readonly
Mailbox Gmail yang diotorisasi (misalnya Gmail khusus CSIRT)
    ↓ subject, body, attachment PDF/TXT/(DOCX opsional)
Incident Intake → validasi, parsing, ekstraksi IOC kandidat
    ↓ deduplikasi berdasar Gmail message ID + mailbox namespace
Incident Case JSON → list_incident_cases / get_incident_case
    ↓
Triage & IOC Investigation (modul tim, terpisah)
```

Tool baru `pull_csirt_gmail_reports` **hanya menarik email saat dipanggil**. Belum ada scheduler otomatis. `limit: 5` berarti *maksimal 5 email cocok filter per panggilan*, bukan harus ada 5 email. Jika `has_more: true`, lanjutkan dengan `next_page_token` pada argumen `page_token`.

## 2. Syarat

- Node.js dan dependensi proyek siap (`npm ci` pada root repo).
- Akun Google yang **diizinkan** untuk membaca mailbox CSIRT.
- Project Google Cloud dan OAuth Desktop Client milik tim (untuk local development).
- Python 3 untuk menjalankan skrip otorisasi lokal.
- Browser untuk menyetujui akses OAuth.
- Server hanya berjalan pada `127.0.0.1` selama testing; **jangan expose HTTP tanpa autentikasi**.

Tidak perlu memasukkan password Gmail ke konfigurasi, chat Hermes, atau GitHub.

## 3. Buat konfigurasi OAuth pada Google Cloud

1. Buka [Google Cloud Console](https://console.cloud.google.com/) → buat/pilih project milik tim.
2. Buka [Gmail API](https://console.cloud.google.com/apis/library/gmail.googleapis.com) → **Enable**.
3. Buka [Google Auth Platform — Branding](https://console.cloud.google.com/auth/branding) → isi nama aplikasi, email dukungan, dan kontak developer.
4. Buka [Audience](https://console.cloud.google.com/auth/audience) → pilih **External / Testing** untuk pengujian; tambahkan alamat akun Gmail yang akan melakukan OAuth ke daftar **Test users**.
5. Buka [Data Access](https://console.cloud.google.com/auth/scopes) → tambahkan scope **`https://www.googleapis.com/auth/gmail.readonly`** (bukan scope pengiriman/penghapusan pesan).
6. Buka [Clients](https://console.cloud.google.com/auth/clients) → **Create client → Desktop app** → download JSON OAuth.

**Jangan commit JSON client, token, atau isi file konfigurasi privat.** Simpan unduhan OAuth JSON di luar folder repo, contoh `~/Kartika Cyber/client_secret_....json`.

## 4. Otorisasi Gmail sekali di Kali WSL

Skrip yang disertakan pada repo: `scripts/setup-gmail-oauth.py`.

Dari root repository:

```bash
# Sesuaikan dengan lokasi asli JSON OAuth Desktop yang diunduh.
CREDS="$HOME/Kartika Cyber/client_secret_XXXXXXXX.apps.googleusercontent.com.json"

python3 scripts/setup-gmail-oauth.py "$CREDS" \
  --email 'alamat-mailbox-csirt@gmail.com' \
  --query 'label:CSIRT' \
  --mailbox-id 'csirt-team'
```

Untuk demo satu email, contoh filter yang lebih spesifik: `--query 'in:inbox subject:CSIRT-TEST-20261115-001'`.

Skrip akan menampilkan URL OAuth Google, membuka callback pada `http://127.0.0.1:8765/oauth2callback`, memverifikasi akun yang dipilih, lalu menyimpan konfigurasi di:

```text
~/.config/csirt-intake/gmail-env.sh   # chmod 600, di luar repo
```

Jangan menyalin refresh token dari file itu ke chat/issue/PR. Peringatan `403 access_denied` biasanya terkait akun yang belum terdaftar sebagai Test user. `HTTP 403` setelah izin diberikan juga dapat berarti Gmail API belum diaktifkan pada project.

**Catatan Google:** untuk aplikasi External dalam status Testing, refresh token scope Gmail bisa kedaluwarsa setelah 7 hari; lakukan otorisasi ulang jika diperlukan. Scope `gmail.readonly` adalah restricted; untuk deployment umum/produksi, tinjau persyaratan verifikasi Google dan penanganan restricted data.

## 5. Jalankan MCP Server dan hubungkan Hermes

Di WSL:

```bash
cd "$HOME/Kartika Cyber/csirt-skill-hermes"
npm ci
npm run test:intake && npm run typecheck && npm run build

source "$HOME/.config/csirt-intake/gmail-env.sh"
mkdir -p "$HOME/.local/share/csirt-intake/cases"
HOST=127.0.0.1 \
INTAKE_DATA_DIR="$HOME/.local/share/csirt-intake/cases" \
npm run dev
```

Jangan jalankan `node tests/mock-gmail-api.mjs` ketika menguji Gmail asli. Variabel `GMAIL_API_BASE_URL` harus **tidak** mengarah ke localhost mock; skrip OAuth otomatis menghapus override tersebut pada saat `source`.

Hubungkan Hermes Windows ke server Streamable HTTP lokal:

```text
Server name: csirt
URL:         http://127.0.0.1:3000/mcp
```

Pada WSL2 umumnya Windows dapat membuka port localhost WSL; jika gagal, periksa `http://127.0.0.1:3000/mcp` dari Windows dan pengaturan firewall/WSL. MCP Server **harus berjalan** untuk menerima panggilan dari Hermes; URL lokal tidak bisa diakses tim dari luar laptop.

## 6. Pengujian lewat Hermes (Gmail asli)

Gunakan perintah chat contoh:

> Gunakan MCP Server csirt. Panggil `pull_csirt_gmail_reports` dengan `limit=1` untuk mengambil laporan terbaru yang cocok dengan filter Gmail CSIRT. Tampilkan `fetched`, `created`, `existing`, `failures`, Case ID, judul, status lampiran, IOC kandidat beserta `found_in`. Panggil `get_incident_case` untuk verifikasi. Jangan jalankan `intake_incident`, `respond_and_report`, atau pemblokiran.

Periksa hasil:

- `fetched: 1` jika ada tepat satu email cocok filter.
- `created: 1` untuk email baru pada penyimpanan kosong; `existing: 1` untuk pesan identik yang sudah pernah disimpan.
- Lampiran berstatus `processed` jika teks berhasil diekstrak; `skipped` beserta alasan jika gagal.
- `ioc_candidates.evidence[].found_in` membedakan `body` dan `attachment:nama-file`.
- `get_incident_case` hanya menerima ID kanonikal seperti `INC-` diikuti 24 karakter heksadesimal.

Untuk retest setelah memperbaiki parser, gunakan direktori **baru** agar kasus lama (`existing`) tidak menyembunyikan hasil pemrosesan terbaru. Jangan hapus database/demo lama tanpa kebutuhan.

## 7. Dependensi lampiran dan batas kemampuan

- **TXT:** didukung tanpa paket tambahan.
- **PDF digital (berisi teks):** memerlukan `pdfjs-dist` di dependencies (`npm ci` akan memasang sesuai lockfile).
- **DOCX:** parser `mammoth` tersedia bila paketnya terpasang; fitur ini belum diuji end-to-end dengan Gmail asli.
- **PDF scan/gambar:** belum mendukung OCR; lampiran bisa diberi status `skipped`.
- Maksimal 2 MiB per lampiran, 6 lampiran diproses per email, 10 email per panggilan tool.
- IOC yang diekstrak (IPv4, URL, domain, MD5, SHA-256) masih **kandidat**. Jangan langsung menyimpulkan malicious atau melakukan blocking.

## 8. Keamanan dan deployment tim

- `gmail.readonly` membatasi operasi Gmail API, **tetapi izin baca secara teknis mencakup mailbox yang diotorisasi**, bukan hanya hasil `GMAIL_QUERY`; gunakan **akun khusus CSIRT** dan pembatasan akses yang sesuai.
- Filter Gmail (`GMAIL_QUERY`) merupakan kebijakan aplikasi, bukan izin OAuth yang membatasi mailbox.
- Simpan token hanya pada server terkontrol, file `0600`, tidak di repo atau log.
- Jangan membuka `/mcp` ke internet dalam konfigurasi lokal tanpa autentikasi dan HTTPS.
- Konten email/lampiran adalah **input tak tepercaya**, termasuk potensi prompt injection. Hasil ekstraksi tidak boleh digunakan sebagai instruksi eksekusi.
- Penyimpanan kasus JSON membutuhkan pembatasan akses, kebijakan retensi, dan backup sebelum penggunaan nyata.
- Jika tim menginginkan akses 24/7, jalankan MCP Server sebagai service pada host bersama, bukan membiarkan `npm run dev` di laptop anggota.

## 9. Troubleshooting

| Gejala | Pemeriksaan |
|---|---|
| `hermes: command not found` di WSL | Hermes Desktop bisa berada di Windows; tidak perlu memasang CLI di Kali |
| 403 saat OAuth | Akun belum jadi test user, salah project atau Gmail API belum Enabled |
| Hasil Gmail masih `mock-csirt-001` | Proses MCP lama/mock masih dipakai; restart tanpa `GMAIL_API_BASE_URL` localhost |
| PDF/TXT `skipped` | Periksa dependensi, validasi ID Gmail attachment (panjang dapat >128), log server lokal; jangan tampilkan token |
| `existing: 1` setelah perbaikan parser | Data kasus lama tersimpan; gunakan storage test baru |
| Error `pdf.destroy is not a function` | Pada PDF.js, cleanup objek loading task dengan `await docTask.destroy()` |
| Hermes tidak menemukan tool | Pastikan MCP Server aktif dan URL endpoint tepat; refresh koneksi/restart Hermes |

Referensi API Google: [messages.list](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list), [messages.get](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get), [attachments.get](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages.attachments/get), [OAuth scopes](https://developers.google.com/workspace/gmail/api/auth/scopes).

## 10. Catatan integrasi GitHub / pull request

Fitur Gmail dikembangkan terpisah di branch `feat/gmail-incident-intake`, berbasis `feat/incident-intake` (PR #2). Selama PR #2 belum digabung ke `main`, ajukan PR Gmail dengan base `feat/incident-intake` agar perubahan Wazuh lama tidak ikut muncul sebagai perubahan Gmail. Setelah PR #2 merge, perbarui base PR Gmail ke `main` dan periksa ulang diff serta CI. Jangan otomatis menimpa file konfigurasi tim.

Tidak perlu menambah `docs/` dan `fixtures/` di root karena tim sebelumnya menyepakati dokumentasi yang terkait modul berada di dalam `hermes/skills/incident-intake/`.
