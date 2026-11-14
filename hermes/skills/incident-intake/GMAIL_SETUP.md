# Panduan Konfigurasi Gmail OAuth — CSIRT Incident Intake

Dokumen ini menjelaskan cara menghubungkan mailbox Gmail ke **MCP Server CSIRT** menggunakan **Google OAuth 2.0**. Konfigurasi dilakukan oleh pengelola MCP Server; pengguna Hermes tidak perlu menyimpan kredensial Gmail masing-masing jika memakai satu server CSIRT bersama.

## 1. Prasyarat

Pastikan tersedia:

- Repository `csirt-skill-hermes` dan dependensinya.
- **Node.js**, **npm**, dan **Python 3**.
- Akses ke **Google Cloud Console** untuk mengelola proyek dan OAuth Client.
- Akun Gmail yang akan digunakan sebagai mailbox CSIRT.
- Browser untuk memberikan persetujuan OAuth.

> Gunakan mailbox khusus CSIRT jika server akan digunakan bersama. Jangan memasukkan kata sandi Gmail ke konfigurasi MCP.

## 2. Membuat proyek Google Cloud

1. Buka [Google Cloud Console](https://console.cloud.google.com/).
2. Pilih proyek yang sudah ada atau klik **New Project** untuk membuat proyek baru.
3. Pastikan proyek tersebut aktif sebelum melanjutkan konfigurasi.

## 3. Mengaktifkan Gmail API

1. Buka **APIs & Services → Library**.
2. Cari **Gmail API**.
3. Klik **Enable**.

Tautan langsung: [Gmail API](https://console.cloud.google.com/apis/library/gmail.googleapis.com).

## 4. Mengonfigurasi OAuth 2.0

1. Buka **Google Auth Platform → Branding**. Lengkapi nama aplikasi, email dukungan, dan informasi kontak yang diminta.
2. Buka **Audience**. Untuk pengujian dengan akun di luar organisasi Google Workspace, pilih **External** dan status **Testing**, kemudian tambahkan alamat Gmail yang akan diotorisasi pada **Test users**.
3. Buka **Data Access**. Tambahkan scope berikut:

   ```text
   https://www.googleapis.com/auth/gmail.readonly
   ```

4. Buka **Clients → Create client**.
5. Pilih jenis aplikasi **Desktop app**, beri nama client, lalu buat.
6. Unduh file konfigurasi OAuth Client dalam format **JSON**.

Simpan file JSON di lokasi privat **di luar repository**. Jangan menyimpan file ini di dalam repository atau membagikannya kepada pengguna lain.

## 5. Menyiapkan mailbox dan dependensi

Di Gmail, buat label **`CSIRT`** dan terapkan pada pesan yang ingin diproses. Bila menggunakan filter lain, sesuaikan nilai `--query` pada langkah berikutnya; misalnya `in:inbox` untuk pesan di Inbox.

Dari direktori utama repository, pasang dependensi:

```bash
npm ci
```

## 6. Menghubungkan Gmail melalui OAuth

Jalankan skrip otorisasi yang tersedia di repository:

```bash
python3 scripts/setup-gmail-oauth.py "/lokasi-privat/oauth-client.json" \
  --email "csirt@example.com" \
  --query "label:CSIRT" \
  --mailbox-id "csirt-mailbox"
```

Ganti:

- `/lokasi-privat/oauth-client.json` dengan lokasi file JSON OAuth yang diunduh.
- `csirt@example.com` dengan alamat Gmail yang benar-benar akan dihubungkan.
- `label:CSIRT` dengan pencarian Gmail yang sesuai kebutuhan.
- `csirt-mailbox` dengan ID unik untuk mailbox tersebut.

Skrip akan memberikan URL persetujuan Google. Buka URL tersebut di browser, pilih akun Gmail yang sesuai, lalu setujui akses **read-only**. Skrip memverifikasi identitas akun sebelum menyimpan konfigurasi privat ke:

```text
~/.config/csirt-intake/gmail-env.sh
```

File tersebut berisi konfigurasi OAuth dan token; **jangan unggah ke repository**.

## 7. Menjalankan MCP Server

Masih dari direktori utama repository, muat konfigurasi OAuth dan gunakan direktori penyimpanan kasus yang persisten:

```bash
source "$HOME/.config/csirt-intake/gmail-env.sh"
mkdir -p "$HOME/.local/share/csirt-intake/cases"

HOST=127.0.0.1 \
INTAKE_DATA_DIR="$HOME/.local/share/csirt-intake/cases" \
npm run dev
```

Untuk instalasi lokal, endpoint MCP tersedia di:

```text
http://127.0.0.1:3000/mcp
```

Server harus tetap berjalan saat Hermes menggunakan MCP Tools. Perintah `npm run dev` ditujukan untuk pengembangan; deployment bersama memerlukan layanan server terkelola, HTTPS, dan autentikasi.

## 8. Menghubungkan Hermes

1. Buka konfigurasi **MCP Server / Connector** pada Hermes.
2. Tambahkan koneksi bertipe **HTTP MCP (Streamable HTTP)**.
3. Masukkan nama koneksi, misalnya `csirt`.
4. Isi URL endpoint MCP. Untuk penggunaan lokal: `http://127.0.0.1:3000/mcp`.
5. Simpan koneksi dan pastikan tool `pull_csirt_gmail_reports` tersedia.

Jika menggunakan server bersama, gunakan URL HTTPS yang disediakan pengelola sistem, bukan alamat `127.0.0.1` dari perangkat pengguna.

## 9. Memverifikasi integrasi

Pada Hermes, minta agent menjalankan `pull_csirt_gmail_reports` dengan `limit=1`. Jika mailbox berisi pesan yang cocok dengan `--query`, tool akan mengambil maksimal satu pesan dan mengembalikan informasi Incident Case. Gunakan `get_incident_case` dengan Case ID yang dihasilkan untuk memeriksa hasil penyimpanan.

Proses pembacaan Gmail menggunakan scope `gmail.readonly`; Incident Intake tidak mengirim, menghapus, atau memblokir pesan.

---

**Keamanan:** batasi akses ke mailbox dan MCP Server, simpan JSON OAuth serta token di luar Git, dan jangan mengekspos endpoint lokal tanpa autentikasi. Scope `gmail.readonly` memberi izin membaca mailbox yang diotorisasi; filter `--query` bukan pembatasan izin OAuth. Penggunaan aplikasi untuk banyak pengguna atau data Gmail restricted harus mengikuti kebijakan Google yang berlaku.

**Referensi resmi:** [Google Auth Platform](https://console.cloud.google.com/auth/overview) · [Gmail API](https://developers.google.com/workspace/gmail/api) · [Gmail API OAuth scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)
