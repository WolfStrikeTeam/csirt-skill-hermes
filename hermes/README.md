# Setup Hermes untuk CSIRT

Folder ini berisi persona, skill, dan konfigurasi supaya [Hermes Agent](https://hermes-agent.nousresearch.com/docs) bisa membaca insiden di TheHive dan menyimpulkannya seperti analis CSIRT.

```
hermes/
├── SOUL.md                  # persona: Hermes sebagai analis CSIRT
├── config.example.yaml      # potongan config: skill tim + koneksi TheHive
└── skills/
    └── security/
        └── incident-summary/
            └── SKILL.md     # skill: simpulkan satu case TheHive
```

## Prasyarat

- Hermes Agent sudah terpasang.
- Node.js (untuk menjalankan `thehive-mcp` lewat `npx`).
- Akses ke **TheHive 5** dan API key-nya. `thehive-mcp` diuji di TheHive 5.4; TheHive 4 belum tentu jalan.

## Langkah setup

**1. Pasang persona.** Hermes hanya membaca `SOUL.md` dari folder home-nya, bukan dari folder project. Jadi salin:

```bash
cp hermes/SOUL.md ~/.hermes/SOUL.md
```

Kalau kamu sudah punya `SOUL.md` sendiri, backup dulu.

**2. Daftarkan skill dan TheHive.** Buka `~/.hermes/config.yaml`, lalu tambahkan isi [`config.example.yaml`](config.example.yaml). Ganti `<path-ke-clone>`, alamat TheHive, dan API key.

**3. Muat ulang.** Di dalam sesi Hermes jalankan `/reload-mcp`, atau buka sesi baru.

**4. Coba.**

```
/incident-summary simpulkan case #1
```

Atau cukup tulis "tolong simpulkan case #1". Hermes akan memilih skill ini sendiri.

## Keamanan

- Tool yang menulis ke TheHive (membuat, mengubah, menutup case, menjalankan analyzer) **mati secara default**. Biarkan begitu sampai tim sepakat.
- API key TheHive cukup pakai akun dengan hak baca.
- Jangan commit `config.yaml` atau API key asli ke repo ini.
