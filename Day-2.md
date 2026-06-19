# 📘 Wazuh for Security Engineers — Day 2

> Materi pembelajaran berdasarkan **Wazuh Training Course Syllabus (4-Day Course)**
> Software version: **Wazuh 4.14.4+**

---

## 🎯 Tujuan Hari Ini

Di akhir Day 2, kamu akan bisa:

- Memahami cara kerja log analysis engine dan bagaimana log mengalir dari agent ke manager
- Membedakan proses **collection** vs **analysis**
- Memahami fase **pre-decoding → decoding → rule matching**
- Mengetahui lokasi penyimpanan log dan alert
- Memahami konsep **atomic rule** vs **composite rule**
- Memahami rule hierarchy, parent-child relationship, dan alert level
- Membuat **decoder** dan **rule** custom untuk aplikasi sendiri
- Menguji decoder/rule yang dibuat

---

## 📑 Daftar Isi Day 2

1. [Log Analysis](#1-log-analysis)
2. [Wazuh Ruleset](#2-wazuh-ruleset)
3. [Decoders and Rules](#3-decoders-and-rules)
4. [Ringkasan Lab Hari Ini](#4-ringkasan-lab-hari-ini)
5. [Quiz Cek Pemahaman](#5-quiz-cek-pemahaman)

---

## 1. Log Analysis

### Kemampuan Log Analysis Engine

Inti dari Wazuh sebenarnya adalah **mesin analisis log**-nya. Engine ini bertugas:

- Membaca log mentah dari berbagai sumber (file log, syslog, Windows Event Log, output command, dll.)
- Mengekstrak informasi penting dari log tersebut (IP, user, status, dll.)
- Mencocokkan event dengan ruleset untuk menentukan apakah perlu menghasilkan **alert**

### Collection vs Analysis — Dua Proses yang Berbeda

Ini konsep yang sering tertukar bagi pemula, jadi penting dipahami betul:

| Aspek | **Collection** | **Analysis** |
|---|---|---|
| Dilakukan oleh | **Agent** (atau manager untuk syslog remote) | **Manager** |
| Tugas | Membaca file log, syslog, event log | Decoding + rule matching |
| Output | Mengirim baris log mentah ke manager | Menghasilkan alert jika cocok rule |
| Komponen | `logcollector` | `analysisd` |

```
┌─────────────────────┐         ┌──────────────────────────┐
│       AGENT          │         │         MANAGER           │
│                       │         │                            │
│  logcollector         │ event   │  analysisd                │
│  (membaca file log,   │ ──────▶│  (pre-decode → decode      │
│   syslog, dll)        │         │   → rule matching)         │
└─────────────────────┘         └──────────────┬─────────────┘
                                                  │ alert (jika match)
                                                  ▼
                                          alerts.log / alerts.json
                                                  │
                                                  ▼
                                            Wazuh Indexer
```

### Mengekstrak Konten Pesan Log

Setiap baris log pada dasarnya hanyalah **teks**. Tugas Wazuh adalah mengubah teks tersebut menjadi **field-field terstruktur** yang bisa dianalisis. Contoh log SSH gagal login:

```
Mar 10 10:15:32 server01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
```

Setelah diproses oleh decoder, field yang diekstrak menjadi:

```json
{
  "program_name": "sshd",
  "srcip": "192.168.1.100",
  "srcport": "54321",
  "dstuser": "admin"
}
```

Field-field inilah yang kemudian dipakai oleh **rule** untuk menentukan apakah event ini perlu dialertkan.

### Alur Pipeline Lengkap (Fase Analisis)

```
Raw log line
     │
     ▼
┌─────────────────┐
│  PRE-DECODING     │  ← ekstrak metadata umum: timestamp, hostname, program_name
└────────┬─────────┘
         ▼
┌─────────────────┐
│   DECODING        │  ← ekstrak field spesifik: srcip, user, dstport, dll (via regex)
└────────┬─────────┘
         ▼
┌─────────────────┐
│  RULE MATCHING    │  ← cocokkan field hasil decode dengan kondisi pada rule
└────────┬─────────┘
         ▼
   Alert dihasilkan (jika rule level > 0 dan cocok)
```

> 💡 Tiga fase ini (**pre-decoding, decoding, rule-based analysis**) akan jadi fondasi penting saat kita masuk ke pembuatan custom decoder & rule di bagian 3.

### Lokasi File Log dan Alert

| File | Lokasi | Isi |
|---|---|---|
| `ossec.log` | `/var/ossec/logs/ossec.log` | Log internal Wazuh sendiri (status servis, error) |
| `alerts.log` | `/var/ossec/logs/alerts/alerts.log` | Alert dalam format teks biasa |
| `alerts.json` | `/var/ossec/logs/alerts/alerts.json` | Alert dalam format JSON (dipakai untuk indexing) |
| `archives.log` / `archives.json` | `/var/ossec/logs/archives/` | **Semua** event (bukan hanya yang menghasilkan alert) — perlu diaktifkan manual |

```bash
# Tail alert secara real-time
tail -f /var/ossec/logs/alerts/alerts.json | jq

# Mengaktifkan logging semua event (termasuk yang tidak alert)
# di ossec.conf manager:
```
```xml
<global>
  <logall>yes</logall>
  <logall_json>yes</logall_json>
</global>
```

> ⚠️ Mengaktifkan `logall` akan meningkatkan penggunaan disk secara signifikan — gunakan hanya saat dibutuhkan untuk debugging mendalam (mirip saat kamu melakukan analisis HTTP log forensik pada insiden — kamu ingin **semua** request, bukan cuma yang "mencurigakan").

### Monitoring Network Devices via Syslog

Untuk perangkat yang tidak bisa memasang agent (router, firewall, switch), Wazuh manager bisa menerima log via **syslog** langsung:

```xml
<!-- di ossec.conf MANAGER -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.1.0/24</allowed-ips>
</remote>
```

Lalu di sisi device (misal router Cisco), konfigurasi syslog diarahkan ke IP Wazuh manager port 514.

### Dukungan Regulatory Compliance

Wazuh ruleset sudah memiliki **mapping otomatis** ke berbagai standar regulasi:

| Standar | Contoh Penerapan |
|---|---|
| **PCI DSS** | Deteksi akses tidak sah ke data kartu kredit |
| **HIPAA** | Audit akses ke data kesehatan |
| **GDPR** | Pemantauan akses data pribadi |
| **SOC 2** | Kontrol akses dan integritas sistem |

Setiap rule di Wazuh punya tag `<group>` yang memetakan ke standar ini, sehingga laporan compliance bisa digenerate otomatis dari Dashboard.

### 🧪 Lab Exercise: Log Analysis

1. **Generate a brute force attack** — melancarkan simulasi serangan brute force SSH ke agent lab.
2. **Analyze the log entries** — memeriksa alert yang dihasilkan dari serangan tersebut.
3. **Look up and trace Wazuh rules** — menelusuri rule mana yang ter-trigger dan memahami strukturnya.

---

## 2. Wazuh Ruleset

### Atomic Rule vs Composite Rule

| Tipe | Definisi | Contoh |
|---|---|---|
| **Atomic Rule** | Menganalisis **satu event tunggal** | "Login SSH gagal" → 1 alert per kegagalan |
| **Composite Rule** | Mengkorelasikan **beberapa event** dalam rentang waktu tertentu | "5x login SSH gagal dalam 2 menit" → alert brute force |

```xml
<!-- Contoh ATOMIC rule -->
<rule id="100100" level="5">
  <if_sid>5716</if_sid>
  <match>invalid user</match>
  <description>Percobaan login dengan user yang tidak valid</description>
</rule>

<!-- Contoh COMPOSITE rule -->
<rule id="100101" level="10" frequency="5" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <description>Kemungkinan brute force: 5x login user invalid dalam 2 menit</description>
  <group>authentication_failures,</group>
</rule>
```

### Rule yang Menghasilkan Alert vs Parent Rule

- **Rule yang menghasilkan alert**: rule dengan kondisi spesifik yang ketika cocok, langsung menghasilkan alert (selama level > 0).
- **Parent rule**: rule "umum" yang dipakai sebagai **basis** untuk rule turunan (child rules) — biasanya **tidak** menghasilkan alert sendiri, hanya berfungsi sebagai filter awal.

```xml
<!-- Parent rule: hanya mengelompokkan semua log sshd -->
<rule id="5700" level="0">
  <decoded_as>sshd</decoded_as>
  <description>Pesan SSHD (grouping rule)</description>
</rule>

<!-- Child rule: mewarisi dari rule 5700 -->
<rule id="5716" level="5">
  <if_sid>5700</if_sid>
  <match>Failed password</match>
  <description>Login SSH gagal</description>
</rule>
```

### Rule Hierarchy & Parent-Child Relationship

```
Rule 5700 (level 0, parent — semua pesan sshd)
   │
   ├── Rule 5716 (level 5 — failed password)
   │      │
   │      └── Rule 100100 (level 5 — failed password + invalid user)
   │             │
   │             └── Rule 100101 (level 10, composite — brute force, frequency=5)
   │
   └── Rule 5715 (level 3 — successful login)
```

> 💡 Keuntungan hierarki ini: engine analisis **tidak perlu mengecek semua rule dari awal** untuk tiap event. Begitu sebuah event "lolos" parent rule (`if_sid`), Wazuh hanya akan mengecek child-child di bawahnya — jauh lebih efisien. Ini akan dibahas lebih dalam di modul **Wazuh Ruleset Traversal** (Day 3).

### Alert Level (0–15) dan Relevansi Keamanannya

| Level | Kategori | Contoh |
|---|---|---|
| 0 | Tidak ada alert (hanya grouping/parent rule) | Pesan log biasa |
| 1–3 | Informational / low priority | Login sukses, perubahan minor |
| 4–6 | Kecurigaan rendah | Beberapa kali login gagal |
| 7–9 | Kecurigaan sedang | Error sistem berulang, policy violation |
| 10–12 | Kecurigaan tinggi | Brute force terdeteksi, multiple attack signature |
| 13–15 | **Kritis** | Rootkit terdeteksi, serangan berhasil, kompromi sistem |

> Semakin tinggi level, semakin Wazuh "yakin" bahwa event tersebut adalah ancaman nyata — bukan sekadar derajat severity teknis biasa.

### Frequency dan Timeframe pada Composite Rule

Dua atribut kunci untuk membuat composite rule:

```xml
<rule id="100101" level="10" frequency="5" timeframe="120">
```

- **`frequency`** — jumlah kali event harus terjadi sebelum rule ter-trigger.
- **`timeframe`** — rentang waktu (dalam detik) di mana `frequency` tersebut dihitung.

Contoh: `frequency="5" timeframe="120"` artinya "5 kejadian dalam 120 detik (2 menit)".

### Custom Rule ID Range

Wazuh sudah memakai range ID tertentu untuk ruleset bawaan. **Jangan** membuat custom rule dengan ID yang bertabrakan!

| Range ID | Peruntukan |
|---|---|
| 0 – 99,999 | Ruleset bawaan Wazuh (jangan dipakai untuk custom rule) |
| **100,000 – 119,999** | **Disarankan untuk custom rule buatan sendiri** |
| 120,000+ | Tersedia untuk kebutuhan custom lanjutan |

> ✅ Selalu gunakan ID ≥ 100000 untuk rule buatanmu sendiri, agar tidak konflik saat ruleset bawaan di-update oleh Wazuh.

### Ignore Timers — Mencegah Alert Flood

Untuk composite rule yang sudah trigger, kamu bisa menambahkan `ignore` agar rule yang sama tidak terus-menerus alert dalam waktu singkat:

```xml
<rule id="100101" level="10" frequency="5" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <description>Brute force terdeteksi</description>
  <ignore>600</ignore> <!-- jangan alert lagi untuk 600 detik -->
</rule>
```

### Rule Group Tags & Compliance Mapping

```xml
<rule id="100101" level="10" frequency="5" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <description>Brute force terdeteksi</description>
  <group>authentication_failures,pci_dss_10.2.4,gdpr_IV_35.7.d,</group>
</rule>
```

Tag `<group>` berfungsi ganda:
1. Mengelompokkan rule untuk pencarian/filter di Dashboard.
2. **Memetakan rule ke kontrol regulasi spesifik** (contoh: `pci_dss_10.2.4` = requirement PCI DSS poin 10.2.4).

### MITRE ATT&CK Mapping

Rule juga bisa di-tag dengan teknik MITRE ATT&CK:

```xml
<rule id="100102" level="12">
  <if_sid>100101</if_sid>
  <description>Brute force SSH - kemungkinan T1110</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

Ini memungkinkan Dashboard menampilkan **MITRE ATT&CK Navigator** yang memvisualisasikan teknik mana saja yang terdeteksi di lingkunganmu.

---

## 3. Decoders and Rules

### Rules, Decoders, dan Pre-decoders

| Komponen | Fungsi |
|---|---|
| **Pre-decoder** | Mengekstrak field umum: `timestamp`, `hostname`, `program_name` — biasanya otomatis dari format syslog standar |
| **Decoder** | Mengekstrak field **spesifik** sesuai jenis log (misal: `srcip`, `dstuser`, `status`) menggunakan regex |
| **Rule** | Mencocokkan kondisi pada field yang sudah diekstrak decoder, lalu memutuskan apakah perlu alert |

### Pre-decoder vs Decoder — Detail

**Pre-decoding** menangani bagian "header" log standar:
```
Mar 10 10:15:32 server01 sshd[12345]: Failed password ...
└──────┬──────┘ └───┬──┘ └────┬────┘
  timestamp      hostname   program_name (+pid)
```

**Decoding** menangani bagian "isi" / payload spesifik yang butuh regex custom:
```
... Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
                                    └──────┬──────┘    └────┬─────┘  └──┬──┘
                                       dstuser            srcip       srcport
```

### Struktur Decoder

```xml
<decoder name="myapp-login">
  <program_name>myapp</program_name>
</decoder>

<decoder name="myapp-login-failed">
  <parent>myapp-login</parent>
  <prematch>Login failed for user</prematch>
  <regex>Login failed for user (\S+) from (\S+)</regex>
  <order>dstuser,srcip</order>
</decoder>
```

Penjelasan elemen:
- **`<parent>`** — decoder ini hanya dicek jika decoder induknya sudah cocok (efisiensi, mirip parent rule).
- **`<prematch>`** — filter cepat berupa string biasa, sebelum regex penuh dijalankan (lebih hemat resource).
- **`<regex>`** — pola untuk mengekstrak data; tiap grup `()` jadi satu field.
- **`<order>`** — urutan nama field sesuai urutan grup regex.

### Regular Expressions di Wazuh

Wazuh memakai sintaks regex dengan beberapa "shortcut" khusus:

| Token | Arti |
|---|---|
| `\S+` | Satu atau lebih karakter non-spasi |
| `\d+` | Satu atau lebih digit |
| `\w+` | Karakter alfanumerik |
| `.*` | Karakter apapun (greedy) |
| `(...)` | Grup yang diekstrak menjadi field |

Contoh regex untuk log custom:
```
Login failed for user admin from 192.168.1.100
```
```xml
<regex>Login failed for user (\S+) from (\S+)</regex>
<order>dstuser,srcip</order>
```

### Contoh Lengkap: Decoder + Rule untuk Aplikasi Custom

Misalnya kamu punya log dari aplikasi finance pribadi (PHP) yang menulis ke syslog:

```
Jun 19 10:00:00 myserver financeapp: AUTH_FAIL user=bagus ip=10.0.0.5 reason=invalid_password
```

**Decoder:**
```xml
<decoder name="financeapp">
  <program_name>financeapp</program_name>
</decoder>

<decoder name="financeapp-auth-fail">
  <parent>financeapp</parent>
  <prematch>AUTH_FAIL</prematch>
  <regex>user=(\S+) ip=(\S+) reason=(\S+)</regex>
  <order>dstuser,srcip,reason</order>
</decoder>
```

**Rule:**
```xml
<rule id="100200" level="0">
  <decoded_as>financeapp</decoded_as>
  <description>Pesan dari FinanceApp (parent/grouping)</description>
</rule>

<rule id="100201" level="5">
  <if_sid>100200</if_sid>
  <match>AUTH_FAIL</match>
  <description>Login gagal di FinanceApp: user $(dstuser) dari $(srcip)</description>
  <group>authentication_failures,</group>
</rule>

<rule id="100202" level="10" frequency="5" timeframe="300">
  <if_matched_sid>100201</if_matched_sid>
  <same_source_ip />
  <description>Kemungkinan brute force di FinanceApp dari IP yang sama</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

> 💡 **Relevansi langsung untukmu:** Pola ini bisa kamu terapkan ke aplikasi finance pribadi PHP/MySQL yang kamu bangun — tinggal tambahkan logging `AUTH_FAIL` semacam ini ke syslog, lalu decoder & rule di atas bisa langsung mendeteksi percobaan brute force ke aplikasimu sendiri.

### Testing Custom Decoder dan Rule

Wazuh menyediakan tool CLI `wazuh-logtest` untuk menguji decoder/rule **tanpa** perlu log sungguhan masuk dulu:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Lalu masukkan baris log uji secara interaktif:
```
Jun 19 10:00:00 myserver financeapp: AUTH_FAIL user=bagus ip=10.0.0.5 reason=invalid_password
```

Output akan menunjukkan:
```
**Phase 1: Completed pre-decoding.
        full event: 'Jun 19 10:00:00 myserver financeapp: AUTH_FAIL ...'
        hostname: 'myserver'
        program_name: 'financeapp'

**Phase 2: Completed decoding.
        name: 'financeapp-auth-fail'
        dstuser: 'bagus'
        srcip: '10.0.0.5'
        reason: 'invalid_password'

**Phase 3: Completed filtering (rules).
        id: '100201'
        level: '5'
        description: 'Login gagal di FinanceApp: user bagus dari 10.0.0.5'
```

> ✅ `wazuh-logtest` adalah tool **paling penting** untuk dikuasai — selalu uji decoder/rule barumu di sini dulu sebelum deploy ke produksi.

### Wazuh Dynamic JSON Decoder

Untuk log yang sudah berformat **JSON**, Wazuh punya decoder bawaan (`json`) yang otomatis mem-parsing **semua field** tanpa perlu menulis regex manual:

```xml
<decoder name="myapp-json">
  <program_name>myapp</program_name>
</decoder>

<decoder name="myapp-json-child">
  <parent>myapp-json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

Contoh log JSON:
```json
{"event":"login_failed","user":"admin","src_ip":"10.0.0.5","status":"denied"}
```

Setelah diproses dynamic JSON decoder, semua key JSON otomatis tersedia sebagai field (`event`, `user`, `src_ip`, `status`) tanpa perlu regex — rule bisa langsung memakai:

```xml
<rule id="100210" level="5">
  <if_sid>100200</if_sid>
  <field name="status">denied</field>
  <description>Login ditolak: user $(user) dari $(src_ip)</description>
</rule>
```

> 💡 Ini sangat cocok untuk integrasi dengan **Suricata** (lab exercise di bawah) karena Suricata native menghasilkan log dalam format JSON (`eve.json`).

### Best Practices Adaptasi Ruleset

1. **Jangan edit ruleset bawaan langsung** — selalu buat file custom baru:
   ```
   /var/ossec/etc/rules/local_rules.xml
   /var/ossec/etc/decoders/local_decoder.xml
   ```
2. Gunakan ID range ≥ 100000 untuk menghindari konflik saat update.
3. Selalu uji dengan `wazuh-logtest` sebelum deploy.
4. Restart manager setelah deploy rule/decoder baru:
   ```bash
   sudo systemctl restart wazuh-manager
   ```
5. Mulai dari rule **spesifik** dan **level rendah**, lalu naikkan level secara bertahap setelah false-positive tervalidasi rendah.

### 🧪 Lab Exercise: Decoders and Rules

1. **Modify an existing rule** — mengubah frequency dan/atau alert level rule bawaan.
2. **Write a custom decoder** — membuat decoder untuk pesan log spesifik.
3. **Create custom rules** — membuat rule yang mencocokkan pesan log tertentu dan menetapkan alert level.
4. **Develop an advanced custom rule** — berdasarkan rule SSHD yang sudah ada (parent-child, composite).
5. **Deploy Suricata** pada agent dan konfigurasi Wazuh untuk mengonsumsi serta mengalertkan log JSON-nya.

---

## 4. Ringkasan Lab Hari Ini

Sesuai *Laboratory Exercises Summary* (**Session 2 – Detection & Rules**):

| Lab | Skill yang Dilatih |
|---|---|
| **[2a]** Brute Force Attack | Simulasi serangan, analisis alert |
| **[2b]** Assess Several Malicious Alerts | Penilaian alert, analisis ancaman |
| **[2c]** Looking Up Rules | Pencarian & identifikasi rule |
| **[2d]** Write a Custom Decoder | Pembuatan decoder custom, parsing log |
| **[2e]** Write a Sibling Decoder | Konfigurasi decoder sibling, decoder chaining |
| **[2f]** Wazuh's Dynamic JSON Decoder | JSON decoding, ekstraksi field dinamis |

---

## 5. Quiz Cek Pemahaman

1. Apa perbedaan antara proses yang dilakukan oleh **logcollector** (agent) dan **analysisd** (manager)?
2. Jelaskan kapan sebuah rule disebut **parent rule** dan mengapa biasanya levelnya `0`.
3. Pada rule composite, apa fungsi atribut `frequency` dan `timeframe`?
4. Berapa range ID yang aman dipakai untuk custom rule, dan mengapa harus dihindari range di bawahnya?
5. Apa fungsi tag `<group>` selain untuk pengelompokan biasa?
6. Tool apa yang digunakan untuk menguji decoder/rule baru sebelum production, dan apa tiga "phase" yang ditampilkannya?
7. Mengapa log berformat JSON lebih mudah diproses dibanding log syslog biasa di Wazuh?

> 💬 Kirim jawabanmu kalau ingin aku review, atau ketik **"lanjut ke Day 3"** untuk masuk ke materi **CDB Lists**, **Wazuh Ruleset Traversal**, **Indexer Pipeline**, **File Integrity Monitoring**, **Vulnerability Detection**, dan **Rootkit Detection**.

---

📌 *File ini adalah bagian 2 dari 4. Lihat juga `Day1-README.md` untuk materi pengantar, arsitektur, dan setup agent.*
