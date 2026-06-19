# 📘 Wazuh for Security Engineers — Day 1

> Materi pembelajaran berdasarkan **Wazuh Training Course Syllabus (4-Day Course)**
> Software version: **Wazuh 4.14.4+**

---

## 🎯 Tujuan Hari Ini

Di akhir Day 1, kamu akan bisa:

- Menjelaskan apa itu Wazuh dan kenapa perusahaan memakainya
- Memahami arsitektur Wazuh dan komunikasi aman antar komponen
- Memahami konsep cluster Wazuh server (master/worker)
- Melakukan konfigurasi dasar manager dan agent
- Mendaftarkan (register) agent Linux & Windows ke Wazuh server
- Bernavigasi di Wazuh Dashboard
- Melakukan upgrade agent secara remote
- Mengatur konfigurasi agent secara terpusat (centralized configuration)

---

## 📑 Daftar Isi Day 1

1. [Introduction to Wazuh](#1-introduction-to-wazuh)
2. [Architecture and Secure Communication](#2-architecture-and-secure-communication)
3. [Wazuh Server Cluster](#3-wazuh-server-cluster)
4. [Wazuh Configuration](#4-wazuh-configuration)
5. [Agent Registration and Connection to Wazuh Server](#5-agent-registration-and-connection-to-wazuh-server)
6. [Wazuh Dashboard](#6-wazuh-dashboard)
7. [Remote Agent Upgrades](#7-remote-agent-upgrades)
8. [Centralized Agent Configuration](#8-centralized-agent-configuration)
9. [Ringkasan Lab Hari Ini](#9-ringkasan-lab-hari-ini)
10. [Quiz Cek Pemahaman](#10-quiz-cek-pemahaman)

---

## 1. Introduction to Wazuh

### Apa itu Wazuh?

**Wazuh** adalah platform keamanan **open source** yang berfungsi sebagai:

- **SIEM** (Security Information and Event Management) — mengumpulkan, menganalisis, dan mengkorelasikan log/event keamanan dari berbagai sumber.
- **XDR** (Extended Detection and Response) — memperluas deteksi dan respons ke endpoint, cloud, network, dan container, tidak hanya log mentah.

### Mengapa perusahaan memakai Wazuh?

| Kebutuhan | Bagaimana Wazuh membantu |
|---|---|
| Deteksi ancaman | Analisis log real-time + ruleset yang luas |
| Compliance (PCI DSS, HIPAA, GDPR, SOC 2) | Mapping rule ke regulasi otomatis |
| Visibilitas infrastruktur | Dashboard terpusat untuk semua agent |
| Deteksi malware/rootkit | Modul rootcheck & FIM |
| Vulnerability management | Cross-reference inventory software vs CVE database |
| Automasi respons | Active Response (block IP, kill process, dll) |
| Cloud security posture | Integrasi AWS, Azure, GCP, Office 365 |

> 💡 **Catatan untuk konteks kamu:** Karena kamu pernah menangani insiden keamanan pada instalasi OJS di Docker (CVE-2024-56525), Wazuh sangat relevan — modul **Log Analysis**, **File Integrity Monitoring**, dan **Docker Integration** di hari-hari berikutnya bisa langsung dipetakan ke skenario forensik yang kamu lakukan secara manual kemarin (cek integritas file, log HTTP, database). Wazuh pada dasarnya mengotomasi proses investigasi semacam itu.

### Latar Belakang Proyek

- Wazuh adalah **fork** dari OSSEC HIDS (Host-based Intrusion Detection System) yang dikembangkan lebih lanjut menjadi platform SIEM/XDR penuh.
- Bersifat open source, dengan dukungan komunitas besar dan juga opsi enterprise support.
- Dirancang untuk dapat diskalakan dari single-node kecil hingga deployment multi-node skala enterprise.

---

## 2. Architecture and Secure Communication

### Tiga Komponen Utama Wazuh

```
┌─────────────┐      events       ┌──────────────┐     index      ┌───────────────┐
│ Wazuh Agent │ ───────────────▶ │ Wazuh Server │ ─────────────▶ │ Wazuh Indexer │
│ (endpoint)  │   (port 1514)     │  (manager)    │                │ (OpenSearch)  │
└─────────────┘                   └──────────────┘                └───────┬───────┘
                                                                            │
                                                                            ▼
                                                                   ┌───────────────┐
                                                                   │ Wazuh         │
                                                                   │ Dashboard     │
                                                                   │ (web UI)      │
                                                                   └───────────────┘
```

#### a. Wazuh Agent
- Software ringan multi-platform (Linux, Windows, macOS, Solaris, AIX, HP-UX).
- Tugas utama: **mengumpulkan data** dari endpoint — log, integritas file, inventaris software, konfigurasi sistem, dll.
- Mengirim data ke Wazuh server secara terenkripsi.

#### b. Wazuh Server (Manager)
- "Otak" dari sistem. Menerima data dari agent, lalu:
  - **Decoding** — mengekstrak field dari log mentah.
  - **Rule matching** — mencocokkan event dengan ruleset untuk menghasilkan alert.
- Mengelola registrasi agent dan distribusi konfigurasi.

#### c. Wazuh Indexer
- Berbasis **OpenSearch**.
- Menyimpan dan mengindeks semua alert dan event agar bisa dicari dengan cepat.

#### d. Wazuh Dashboard
- Web app (berbasis OpenSearch Dashboards) untuk visualisasi, pencarian, dan manajemen.

### Agentless Monitoring

Tidak semua device bisa/perlu memasang agent (misalnya switch, firewall, atau perangkat yang tidak mendukung instalasi software pihak ketiga). Untuk kasus ini Wazuh menyediakan:

- **Agentless monitoring**: server Wazuh terhubung langsung ke device via SSH untuk mengecek perubahan konfigurasi secara periodik.
- Cocok untuk network devices dan sistem dengan akses terbatas.

### Opsi Deployment

| Tipe | Deskripsi | Cocok untuk |
|---|---|---|
| **All-in-one** | Server, indexer, dashboard di satu host | Lab, demo, perusahaan kecil |
| **Single-node** | Mirip all-in-one, satu instance tiap komponen | Produksi skala kecil-menengah |
| **Multi-node (cluster)** | Beberapa instance server/indexer untuk HA & skalabilitas | Enterprise, beban tinggi |

### Komunikasi Aman

- Komunikasi agent ↔ manager dienkripsi menggunakan **AES**.
- Setiap agent memiliki **kunci unik** yang dihasilkan saat proses registrasi.
- Port default:
  - **1514/UDP atau TCP** — agent connection (event data)
  - **1515/TCP** — agent enrollment/registration
  - **55000/TCP** — Wazuh API
  - **9200/TCP** — Wazuh Indexer (OpenSearch)
  - **443/TCP** — Wazuh Dashboard

> 📝 Sesuai prasyarat course: jaringan lab harus mengizinkan outgoing traffic ke port **22 (SSH)**, **3389 (RDP)**, dan **443 (UI)** menuju `*.lab.wazuh.info`.

### Alur Data (Data Flow)

```
Agent collects data → sends to Manager → Pre-decoding → Decoding → Rule matching
→ Alert generated (if matched) → sent to Indexer → visualized in Dashboard
```

---

## 3. Wazuh Server Cluster

Untuk environment yang membutuhkan **high availability** dan **skalabilitas**, beberapa Wazuh server dapat digabung menjadi **cluster**.

### Master Node

- Bertanggung jawab atas:
  - Registrasi agent baru
  - Menyimpan dan mendistribusikan **konfigurasi terpusat** (centralized configuration)
  - Sinkronisasi data ke seluruh worker node

### Worker Node

- Menangani agent yang terhubung padanya — memproses event yang masuk
- **Sinkronisasi** secara berkala dengan master node untuk:
  - Daftar agent
  - File konfigurasi grup
  - Ruleset, decoder, CDB list

### Diagram Konsep Cluster

```
                ┌────────────────┐
                │  Master Node    │  ← satu-satunya yang mendaftarkan agent baru
                │ (registrasi,    │
                │  config master) │
                └───────┬─────────┘
                        │ sinkronisasi
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
   ┌───────────┐  ┌───────────┐  ┌───────────┐
   │ Worker 1  │  │ Worker 2  │  │ Worker 3  │
   │ (agents   │  │ (agents   │  │ (agents   │
   │  group A) │  │  group B) │  │  group C) │
   └───────────┘  └───────────┘  └───────────┘
```

### Pertimbangan Khusus Cluster

- Semua node cluster **harus** menjalankan versi Wazuh yang **sama**.
- Load balancer (eksternal) sering digunakan di depan worker node untuk distribusi agent secara even.
- Saat troubleshooting, penting untuk mengecek **log sinkronisasi cluster** (`cluster.log`) bila ada agent yang tidak ter-update konfigurasinya.
- Worker node **tidak** bisa mendaftarkan agent baru secara independen — pendaftaran tetap melalui master (atau API yang diteruskan ke master).

---

## 4. Wazuh Configuration

### File Konfigurasi Utama

| File | Lokasi (Linux) | Fungsi |
|---|---|---|
| `ossec.conf` | `/var/ossec/etc/ossec.conf` | Konfigurasi utama manager **atau** agent |
| `agent.conf` | `/var/ossec/etc/shared/<group>/agent.conf` | Konfigurasi terpusat per **grup agent** |
| `internal_options.conf` | `/var/ossec/etc/internal_options.conf` | Opsi internal tingkat lanjut (jarang diubah) |
| `local_internal_options.conf` | `/var/ossec/etc/local_internal_options.conf` | Override opsi internal secara lokal |

### Kategori Konfigurasi: Terpusat vs Lokal

Bagian-bagian dalam `ossec.conf` agent **bisa** didistribusikan terpusat dari manager melalui `agent.conf`, tetapi sebagian **harus** dikelola secara lokal di tiap agent. Contoh:

| Dapat Didistribusikan Terpusat | Harus Tetap Lokal |
|---|---|
| `<syscheck>` (FIM rules) | `<client>` (alamat manager) |
| `<localfile>` (log collection) | `<client_buffer>` |
| `<rootcheck>` | Nama/ID agent |
| `<sca>` (Security Configuration Assessment) | Kunci registrasi |
| `<wodle>` (modul tambahan) | |

> ⚠️ Elemen yang berkaitan dengan **identitas dan koneksi agent ke manager** tidak boleh didistribusikan terpusat — agar agent tidak "berebut" konfigurasi koneksi.

### Cara Mengubah Konfigurasi

**1. Via command line (langsung edit file):**
```bash
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

**2. Via Wazuh API / Web App:**
- Dashboard → **Management → Configuration**
- Beberapa pengaturan bisa diubah dan di-push tanpa restart manual (tergantung jenis konfigurasinya).

### Agent Groups & Profiles

- **Agent Groups**: kumpulan agent yang menerima `agent.conf` yang sama. Default group: `default`.
- **Profiles**: cara mengelompokkan konfigurasi berdasarkan kriteria seperti OS, lokasi, atau fungsi server — agar satu agent bisa menerima beberapa "potongan" konfigurasi sekaligus dari beberapa grup.

Contoh struktur grup:

```
/var/ossec/etc/shared/
├── default/
│   └── agent.conf
├── linux-servers/
│   └── agent.conf
├── windows-workstations/
│   └── agent.conf
└── web-servers/
    └── agent.conf      ← misalnya berisi syscheck khusus folder web app (OJS, dsb.)
```

> 💡 Untuk environment seperti server OJS milikmu, kamu bisa membuat grup `journal-servers` dengan `agent.conf` yang fokus memantau direktori upload, config OJS, dan file PHP — supaya kalau ada serangan seperti injeksi konten via REST API lagi, Wazuh langsung mendeteksi perubahan file mencurigakan.

### 🧪 Lab Exercise: Wazuh Configuration

- **Mengelola konfigurasi utama manager** (`ossec.conf`) dan internal options.
- **Implementasi centralized agent configuration** menggunakan agent groups dan profiles.

---

## 5. Agent Registration and Connection to Wazuh Server

### Metode Registrasi Agent

| Metode | Deskripsi |
|---|---|
| **Self-enrollment dengan password** | Agent menjalankan perintah enrollment dengan authentication password ke manager (port 1515) |
| **Registrasi via Dashboard** | Admin generate command/kunci dari UI, lalu jalankan di endpoint |
| **Registrasi via API** | Otomasi mass-deployment menggunakan Wazuh API |
| **Manual key import** | Key di-generate di manager (`manage_agents`), lalu disalin manual ke agent |

### Instalasi Agent — Linux (contoh Ubuntu/Debian)

```bash
# 1. Tambahkan repository Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
  chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee -a /etc/apt/sources.list.d/wazuh.list

apt-get update

# 2. Install agent sambil menentukan alamat manager
WAZUH_MANAGER='ALAMAT_IP_MANAGER' apt-get install wazuh-agent

# 3. Jalankan dan aktifkan service
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

### Instalasi Agent — Windows

```powershell
# Download MSI installer
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.4-1.msi -OutFile wazuh-agent.msi

# Install dengan menentukan alamat manager
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="ALAMAT_IP_MANAGER" WAZUH_REGISTRATION_SERVER="ALAMAT_IP_MANAGER"

# Start service
NET START WazuhSvc
```

### Self-Enrollment dengan Authentication Password

Manager bisa dikonfigurasi agar mewajibkan password saat agent melakukan enrollment, demi mencegah agent rogue mendaftar sembarangan:

```xml
<!-- di ossec.conf manager, dalam <auth> -->
<auth>
  <use_password>yes</use_password>
</auth>
```

Password disimpan di manager pada `/var/ossec/etc/authd.pass`. Saat instalasi agent, password ini disertakan via variabel environment (`WAZUH_REGISTRATION_PASSWORD`) agar proses enrollment otomatis berhasil.

### Verifikasi Konektivitas Agent

```bash
# Di sisi manager
/var/ossec/bin/agent_control -l        # daftar semua agent & statusnya

# Cek log agent
tail -f /var/ossec/logs/ossec.log      # di sisi agent

# Cek log manager terkait koneksi
tail -f /var/ossec/logs/ossec.log      # di sisi manager, cari baris "Agent connected"
```

Status agent yang umum:
- 🟢 **Active** — terhubung dan mengirim data
- 🟡 **Pending** — terdaftar tapi belum pernah connect
- 🔴 **Disconnected** — pernah connect, sekarang putus
- ⚪ **Never connected**

---

## 6. Wazuh Dashboard

### Navigasi Utama

Dashboard Wazuh (berbasis OpenSearch Dashboards) memiliki struktur menu utama:

```
☰ Menu
├── Modules
│   ├── Security Events       ← alert log utama
│   ├── Integrity Monitoring  ← hasil FIM
│   ├── Vulnerability Detection
│   ├── MITRE ATT&CK
│   ├── Security Configuration Assessment
│   └── ...
├── Server Management
│   ├── Rules
│   ├── Decoders
│   ├── CDB Lists
│   └── Groups
├── Management
│   ├── Agents
│   ├── Cluster
│   └── Status
└── Settings
```

### Dashboard Kunci yang Wajib Dikenal

| Dashboard | Fungsi |
|---|---|
| **Security Events** | Melihat semua alert beserta level, rule ID, agent asal |
| **Agents Overview** | Status koneksi semua agent, versi, OS |
| **Agent Detail View** | Drill-down ke satu agent: log, FIM, SCA, inventory |

### Fitur Penting untuk Dieksplorasi

- **Filter & Search** menggunakan KQL (Kibana/OpenSearch Query Language)
- **Discover** — eksplorasi data mentah ala log explorer
- **Visualize** — membuat chart/grafik custom dari data alert
- **Time range picker** — sangat penting untuk investigasi insiden (mirip saat kamu menganalisis HTTP log OJS — di Wazuh ini semua bisa difilter berdasarkan rentang waktu insiden)

> Modul ini sifatnya pengenalan — eksplorasi lebih dalam akan terus dilakukan sepanjang training karena Dashboard dipakai di **hampir semua modul** berikutnya.

---

## 7. Remote Agent Upgrades

### Mengapa Upgrade Terpusat Penting?

Pada deployment dengan ratusan/ribuan agent, upgrade manual satu-satu tidak praktis. Wazuh menyediakan mekanisme **upgrade agent dari manager** tanpa perlu akses langsung ke tiap endpoint.

### Cara Kerja

1. Manager mengirim **paket upgrade** ke agent melalui koneksi yang sudah terenkripsi.
2. Agent menjalankan proses upgrade secara otomatis lalu **restart service**-nya sendiri.
3. Manager memverifikasi versi baru setelah agent kembali online.

### Upgrade via Wazuh API

```bash
# Upgrade single agent (contoh agent ID 003)
curl -k -X PUT "https://MANAGER_IP:55000/agents/003/upgrade" \
  -H "Authorization: Bearer $TOKEN"

# Upgrade banyak agent sekaligus berdasarkan grup
curl -k -X PUT "https://MANAGER_IP:55000/agents/group/is_sync?group_id=web-servers" \
  -H "Authorization: Bearer $TOKEN"
```

### Verifikasi Hasil Upgrade

```bash
curl -k -X GET "https://MANAGER_IP:55000/agents/003" \
  -H "Authorization: Bearer $TOKEN" | jq '.data.affected_items[0].version'
```

Atau melalui Dashboard: **Management → Agents → [pilih agent] → cek kolom Version**.

### Catatan Praktik Baik

- Selalu lakukan upgrade di lingkungan **staging/lab** dahulu.
- Upgrade per grup kecil dulu sebelum massal, untuk mendeteksi masalah kompatibilitas sejak awal.
- Pastikan versi **manager selalu ≥ versi agent** (agent tidak boleh lebih baru dari manager).

---

## 8. Centralized Agent Configuration

### Tujuan

Mengelola konfigurasi banyak agent **dari satu tempat** (manager), tanpa harus login ke tiap endpoint satu-persatu.

### Struktur `agent.conf`

File ini ditempatkan di manager pada:
```
/var/ossec/etc/shared/<nama_grup>/agent.conf
```

Contoh isi `agent.conf` untuk grup `web-servers`:

```xml
<agent_config>
  <syscheck>
    <directories check_all="yes" report_changes="yes" realtime="yes">/var/www/html</directories>
    <directories check_all="yes">/etc/nginx</directories>
  </syscheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
</agent_config>
```

### Langkah Membuat & Menerapkan Grup

**Via CLI:**
```bash
# Membuat grup baru
/var/ossec/bin/agent_groups -a -g web-servers

# Menambahkan agent ke grup
/var/ossec/bin/agent_groups -a -i 003 -g web-servers

# Mengecek agent dalam grup
/var/ossec/bin/agent_groups -l -g web-servers
```

**Via Wazuh API:**
```bash
# Buat grup
curl -k -X POST "https://MANAGER_IP:55000/groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id":"web-servers"}'

# Assign agent ke grup
curl -k -X PUT "https://MANAGER_IP:55000/agents/003/group/web-servers" \
  -H "Authorization: Bearer $TOKEN"
```

**Via Dashboard:**
- Management → **Groups** → Create Group
- Edit konfigurasi grup langsung dari editor XML built-in
- Management → **Agents** → pilih agent → assign ke grup

### Validasi & Propagasi Konfigurasi

- Setelah `agent.conf` diubah, manager menandai status sinkronisasi agent sebagai **outdated** sampai agent benar-benar mengambil (pull) konfigurasi baru — biasanya terjadi otomatis dalam beberapa detik/menit (interval keepalive).
- Cek status sinkronisasi:
```bash
/var/ossec/bin/agent_groups -s -i 003
```
- Jika ada **error syntax XML** di `agent.conf`, agent grup tersebut akan gagal menerapkan konfigurasi — selalu validasi XML sebelum deploy ke grup besar.

### Diagram Alur Propagasi

```
Admin edit agent.conf di grup "web-servers"
        │
        ▼
Manager menyimpan & menandai grup sebagai "perlu sync"
        │
        ▼
Agent (saat keepalive berikutnya) menerima notifikasi config baru
        │
        ▼
Agent men-download agent.conf terbaru → terapkan → restart modul terkait
        │
        ▼
Status berubah dari "outdated" → "synced"
```

---

## 9. Ringkasan Lab Hari Ini

Sesuai *Laboratory Exercises Summary* (**Session 1 – Setup & Agents**):

| Lab | Skill yang Dilatih |
|---|---|
| **[1a]** Prepare Wazuh Server Components | Alert levels, authentication, API connectivity |
| **[1b]** Navigate the Dashboard | Eksplorasi dashboard, familiarisasi interface |
| **[1c]** Register linux-agent | Instalasi agent, self-enrollment |
| **[1d]** Install Windows Agent | Variabel deployment khusus Windows |
| **[1e]** Register via Dashboard | Registrasi agent melalui UI |
| **[1f]** Agent Upgrades | Update agent berbasis manager |
| **[1g]** Centralized Configuration | Agent groups, deployment `agent.conf` |

---

## 10. Quiz Cek Pemahaman

Coba jawab dulu sebelum lanjut ke Day 2 — ini membantu memastikan konsep Day 1 sudah melekat:

1. Apa perbedaan fungsi antara **Wazuh server**, **indexer**, dan **dashboard**?
2. Mengapa elemen `<client>` di `ossec.conf` **tidak** boleh didistribusikan secara terpusat?
3. Pada cluster Wazuh, node mana yang bertanggung jawab mendaftarkan agent baru — master atau worker?
4. Sebutkan 2 metode registrasi agent yang sudah dipelajari hari ini.
5. Apa yang terjadi pada status sinkronisasi grup agent setelah `agent.conf` diedit, sampai agent benar-benar mengambil konfigurasi tersebut?

> 💬 Kirim jawabanmu kalau mau aku cek bareng, atau langsung lanjut **"lanjut ke Day 2"** kalau sudah siap masuk ke materi **Log Analysis**, **Wazuh Ruleset**, dan **Decoders and Rules** — bagian yang biasanya jadi inti dari skill tuning Wazuh.

---

📌 *File ini adalah bagian 1 dari 4 — silakan minta lanjutan untuk Day 2, Day 3, dan Day 4 mengikuti struktur silabus yang sama.*
