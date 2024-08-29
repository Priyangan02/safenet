# **SafeNet: Intrusion Detection and Prevention System (IDPS)**

SafeNet adalah aplikasi Intrusion Detection and Prevention System (IDPS) yang dibangun menggunakan Python dan Django. Aplikasi ini dirancang untuk mendeteksi dan mencegah berbagai jenis serangan jaringan seperti brute force SSH, TCP flood, UDP flood, dan ICMP flood. Selain itu, SafeNet juga terintegrasi dengan Telegram untuk memberikan notifikasi real-time.

## **Fitur Utama**

**Deteksi Brute Force SSH**: Mendeteksi percobaan login SSH yang gagal dan memblokir IP yang mencurigakan.

**Deteksi Flood**: Mengidentifikasi serangan flood TCP, UDP, dan ICMP dan mengambil tindakan yang sesuai.

**Whitelist IP**: Kemampuan untuk menambahkan IP ke daftar putih sehingga tidak diperiksa oleh IDPS, tetapi tetap mencatat aktivitas mencurigakan jika melebihi ambang batas.

**Dashboard Web**: Antarmuka pengguna berbasis web untuk memonitor log aktivitas, mengkonfigurasi pengaturan, dan mengelola IP yang diblokir atau diizinkan.

**Integrasi Telegram**: Mengirim notifikasi langsung ke Telegram admin saat aktivitas mencurigakan terdeteksi.

**Logging Aktivitas**: Mencatat semua aktivitas mencurigakan, termasuk yang berasal dari IP yang terdaftar di whitelist.

**Persyaratan Sistem**

* Python 3.x

* Scapy

* Django 3.x atau lebih baru

* Ubuntu OS (atau sistem berbasis Linux lainnya)

* Akun Telegram dan bot token untuk notifikasi

## **Penggunaan**

* **Home**: Menampilkan log dari IDPS.

* **Config**: Mengaktifkan/menonaktifkan IDPS dan mengatur ambang batas untuk serangan flood dan percobaan login SSH gagal.

* **SSH Success**: Menampilkan log dari login SSH yang berhasil.

* **Banned IP**: Mengelola IP yang diblokir oleh IDPS.

* **Whitelist**: Menambahkan IP yang akan dilewati pemeriksaan IDPS tetapi tetap log aktivitas mencurigakan jika melebihi ambang batas.

## **Kontak**

Untuk pertanyaan atau dukungan lebih lanjut, silakan hubungi priyantoalansyah18@gmail.com.
