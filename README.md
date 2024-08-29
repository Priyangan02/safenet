# **SafeNet: Intrusion Detection and Prevention System (IDPS)**

SafeNet adalah aplikasi Intrusion Detection and Prevention System (IDPS) yang dibangun menggunakan Python dan Django. Aplikasi ini dirancang untuk mendeteksi dan mencegah berbagai jenis serangan jaringan seperti brute force SSH, TCP flood, UDP flood, dan ICMP flood. Selain itu, SafeNet juga terintegrasi dengan Telegram untuk memberikan notifikasi realtime.


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
![Screenshot 2024-08-05 003120](https://github.com/user-attachments/assets/989bbb66-1f3f-4422-b5bb-e04c50b964a2)
* **Config**: Mengaktifkan/menonaktifkan IDPS dan mengatur ambang batas untuk serangan flood dan percobaan login SSH gagal.
![Screenshot 2024-08-05 003454](https://github.com/user-attachments/assets/a72d9347-5313-4f9e-9a28-82eb0ecb2b36)

* **SSH Success**: Menampilkan log dari login SSH yang berhasil.
![Screenshot 2024-08-05 005307](https://github.com/user-attachments/assets/4f441635-51ba-4652-92e8-6b562799f287)

* **Banned IP**: Mengelola IP yang diblokir oleh IDPS.
![Screenshot 2024-08-05 005411](https://github.com/user-attachments/assets/994dc386-86e3-46c1-b567-5ee127e2cddd)

* **Whitelist**: Menambahkan IP yang akan dilewati pemeriksaan IDPS tetapi tetap log aktivitas mencurigakan jika melebihi ambang batas.
![Screenshot 2024-08-05 005755](https://github.com/user-attachments/assets/c81ace70-e94f-4ad4-a46e-7f3912aebba4)

## **Kontak**

Untuk pertanyaan atau dukungan lebih lanjut, silakan hubungi priyantoalansyah18@gmail.com.
