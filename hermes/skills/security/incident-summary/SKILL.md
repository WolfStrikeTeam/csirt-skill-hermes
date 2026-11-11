---
name: incident-summary
description: Tarik satu case insiden dari TheHive lalu buat kesimpulan analis CSIRT (apa yang terjadi, dampak, IOC, MITRE ATT&CK, Cyber Kill Chain, tingkat keyakinan, dan rekomendasi). Pakai saat pengguna minta ringkasan, kesimpulan, atau analisis sebuah case/insiden/alert.
version: 0.1.0
author: Kartika-Cybersex
metadata:
  hermes:
    tags: [csirt, incident-response, thehive, mitre-attack]
    category: security
---

# Incident Summary

Membaca satu case di TheHive secara menyeluruh, lalu menulis kesimpulan yang bisa langsung dipakai analis untuk mengambil keputusan.

## When to Use

- Pengguna minta "simpulkan", "ringkas", "analisis", atau "apa yang terjadi" pada sebuah case atau alert.
- Pengguna memberi nomor case TheHive (misalnya `#42` atau `~123456`) atau judul insiden.
- Sebelum rapat atau serah terima shift, untuk merangkum case yang masih terbuka.

Jangan pakai skill ini untuk membuat case baru atau mengubah data di TheHive.

## Prasyarat

MCP server `thehive` harus aktif di Hermes (lihat `hermes/README.md` di repo tim). Tool-nya terdaftar dengan awalan `mcp_thehive_`, misalnya `mcp_thehive_thehive_get_case`. Di bawah ini nama tool ditulis tanpa awalan.

Kalau tool TheHive tidak tersedia atau `thehive_status` gagal, berhenti dan beri tahu pengguna. Jangan menyimpulkan dari ingatan atau tebakan.

## Procedure

### 1. Tentukan case-nya

- Kalau pengguna memberi nomor atau ID, ambil dengan `thehive_get_case`.
- Kalau hanya memberi kata kunci, cari dengan `thehive_search_cases`. Jika hasilnya lebih dari satu, tampilkan daftar singkat (nomor, judul, severity, status) dan minta pengguna memilih.
- Kalau yang diberikan alert, ambil dengan `thehive_get_alert`. Analisis tetap bisa jalan, tapi sebutkan bahwa ini masih alert, belum case.

### 2. Kumpulkan semua data case

Ambil semuanya sebelum mulai menyimpulkan:

| Data | Tool |
|---|---|
| Detail case (judul, deskripsi, severity, TLP, PAP, tag, status, assignee) | `thehive_get_case` |
| Kronologi | `thehive_case_timeline_summary` |
| Observable / IOC | `thehive_list_observables` |
| Task dan log kerja analis | `thehive_list_tasks`, lalu `thehive_list_task_logs` per task |
| Komentar | `thehive_list_comments` |
| Case serupa | `thehive_get_similar_cases` |

Untuk observable yang sudah pernah dianalisis Cortex, baca hasilnya dengan `thehive_get_job` dan `thehive_summarize_job_report`.

**Jangan menjalankan analyzer baru** (`thehive_run_analyzer`) tanpa izin pengguna. Analyzer bisa mengirim observable ke layanan eksternal. Untuk observable dengan PAP:RED, jangan minta izin sama sekali; cukup catat bahwa observable itu belum diperkaya.

### 3. Analisis

Jawab pertanyaan berikut, dan untuk setiap jawaban catat buktinya:

1. **Apa yang terjadi?** Rangkai kronologi dari timeline, log task, dan komentar.
2. **Siapa dan apa yang terdampak?** Host, akun, layanan, data.
3. **Apakah masih berlangsung?** Cari aktivitas terbaru dan task yang belum selesai.
4. **IOC apa saja?** Kelompokkan per tipe (IP, domain, hash SHA-256/MD5, URL, email). Tandai yang sudah terkonfirmasi berbahaya dari hasil Cortex atau catatan analis.
5. **MITRE ATT&CK.** Petakan ke tactic dan technique (beserta ID, misalnya `T1110.001`). Hanya petakan yang didukung bukti.
6. **Cyber Kill Chain.** Insiden sudah sampai fase mana?
7. **Severity.** Bandingkan severity di TheHive (1 = low, 2 = medium, 3 = high, 4 = critical) dengan penilaianmu sendiri. Kalau berbeda, jelaskan alasannya.
8. **Case serupa.** Apakah ada pola berulang atau kampanye yang sama?
9. **Apa yang belum diketahui?** Data apa yang kurang untuk menyimpulkan dengan yakin?

### 4. Tulis kesimpulan

Pakai format ini persis:

```markdown
## Kesimpulan Case #<nomor>: <judul>

**Ringkasan:** <2-3 kalimat: apa yang terjadi, dampaknya, status saat ini>

| | |
|---|---|
| Severity TheHive | <low/medium/high/critical> |
| Penilaian kami | <low/medium/high/critical> (<alasan singkat bila berbeda>) |
| Keyakinan | <rendah/sedang/tinggi>, <alasan> |
| Status | <masih berlangsung / sudah ditangani / belum jelas> |
| TLP / PAP | <TLP> / <PAP> |

### Kronologi
- <waktu> - <kejadian> (<sumber: observable/log/komentar>)

### Aset terdampak
- <host/akun/layanan> - <dampak>

### IOC
| Tipe | Nilai | Status | Sumber |
|---|---|---|---|

### MITRE ATT&CK
| Tactic | Technique | Bukti |
|---|---|---|

**Cyber Kill Chain:** <fase terjauh yang tercapai>

### Case serupa
- <nomor case> - <kemiripan>, atau "Tidak ditemukan"

### Rekomendasi
1. **[Segera]** <aksi> - <alasan>
2. **[Jangka pendek]** <aksi> - <alasan>
3. **[Pencegahan]** <aksi> - <alasan>

Usulan blokir (perlu persetujuan analis):
- <IP/domain> - <alasan>

### Yang belum diketahui
- <data yang kurang> - <cara mendapatkannya>
```

Hapus bagian yang memang tidak ada isinya, kecuali "Yang belum diketahui". Bagian itu wajib ada.

### 5. Tawarkan tindak lanjut

Setelah kesimpulan ditulis, tawarkan (jangan langsung lakukan):
- Menyimpan kesimpulan sebagai komentar di case.
- Menjalankan analyzer Cortex untuk observable yang belum diperkaya (sebutkan observable mana dan layanan apa).

Semua aksi yang menulis ke TheHive butuh persetujuan eksplisit. Tool penulis juga nonaktif secara default di thehive-mcp.

## Pitfalls

- **Menyimpulkan dari judul saja.** Judul case sering ditulis sebelum investigasi. Selalu baca task log dan komentar.
- **Menyamakan severity alert dengan severity insiden.** Satu alert critical bisa ternyata false positive.
- **Mapping MITRE berlebihan.** Lebih baik dua technique yang terbukti daripada sepuluh yang mungkin.
- **Membocorkan data sensitif.** Jangan menyalin isi bertanda TLP:RED ke saluran di luar sesi ini.
- **Data terpotong.** Kalau daftar observable atau komentar sangat panjang, pastikan semuanya terbaca (pakai paginasi bila ada) sebelum menyimpulkan.

## Verification

Sebelum menyerahkan kesimpulan, cek:
- [ ] Setiap IOC di tabel memang ada di observable atau log case.
- [ ] Setiap technique MITRE punya bukti di kolom "Bukti".
- [ ] Kronologi urut waktu dan setiap baris punya sumber.
- [ ] Bagian "Yang belum diketahui" terisi jujur.
- [ ] Tidak ada aksi yang dijalankan tanpa izin.
