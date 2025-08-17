
# 🌐 Luminet — Lightweight Recon Dashboard / Luminet — Hafif Keşif Panosu

https://github.com/user-attachments/assets/afa9aaf8-586a-4f67-bb67-6a3d5d13e103

[▶️ Luminet Demo Video](video/video.mp4)

---

## 🇹🇷 Türkçe — Proje Özeti

Luminet, bir **IP** veya **domain** girildiğinde yalnızca açık kaynaklı, ücretsiz ve herkese açık veri kaynaklarından (WHOIS / RDAP, DNS, BGP, DNSBL, HTTP/SSL vb.) toplanabilen bilgileri elde edip kullanıcıya şık bir **web arayüzü** üzerinden sunmayı amaçlayan bir projedir.  
Amacı: Ağ keşfini **basit, hızlı, ücretsiz ve erişilebilir** hale getirmek.

---

## 🇬🇧 English — Project Summary

Luminet is an **open-source web application** for IP and domain reconnaissance.  
It aggregates information only from **public and free data sources** (WHOIS / RDAP, DNS, BGP, DNSBL, HTTP/SSL, etc.) and displays it via a lightweight **web UI**.  
Goal: make network reconnaissance **simple, fast, free, and accessible**.

---

## ✨ Özellikler — Features

- **TR:** RDAP / WHOIS özetleri, ASN & BGP prefix ilişkileri  
- **EN:** RDAP / WHOIS parsing & summaries, ASN & BGP prefix mapping  

- **TR:** DNS sorguları (A/AAAA/MX/NS/TXT/CNAME/SOA), DNSSEC kontrolü  
- **EN:** DNS queries (A/AAAA/MX/NS/TXT/CNAME/SOA), DNSSEC checks  

- **TR:** DNSBL sorguları, Reverse-DNS, traceroute & mtr, ping özetleri  
- **EN:** DNSBL lookups, reverse DNS, traceroute & mtr, ping summaries  

- **TR:** Opsiyonel `nmap` port taraması  
- **EN:** Optional port scanning with `nmap`  

- **TR:** HTTP header analizi & SSL sertifika incelemesi  
- **EN:** HTTP header grab & SSL certificate analysis  

- **TR:** Kullanıcı yönetimi + API anahtarı desteği  
- **EN:** User management + API key support  

---

## 📂 Dosyalar — Files Included
- `main.py` — Flask uygulaması (backend) / Flask backend  
- `index.html`, `login.html`, `register.html`, `profile.html` — frontend HTML sayfaları / HTML frontend templates  
- `requirements.txt` — bağımlılıklar / dependencies  
- `README.md` — proje açıklaması / project description  
- `video/` — medya dosyaları (ör. video.mp4) / media assets (e.g. demo.mp4)  

---

## ⚙️ Gereksinimler — Requirements

- **TR:** Linux (Ubuntu/Debian önerilir), Python 3.10+  
- **EN:** Linux (Ubuntu/Debian recommended), Python 3.10+  

**Opsiyonel paketler:** `mtr`, `nmap` (bazı özellikler için gerekli olabilir).  
**Python bağımlılıkları:** `requirements.txt` dosyasında listelenmiştir.  

---

## 🚀 Kurulum & Çalıştırma — Installation & Run

### 🇹🇷 Türkçe
```bash
# 1) Sistem paketlerini kur
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mtr nmap

# 2) Sanal ortam oluştur
python3 -m venv .venv
source .venv/bin/activate

# 3) Python bağımlılıklarını kur
pip install -r requirements.txt

# 4) Veritabanı oluştur
python3 -c "from main import db, app; \
with app.app_context(): db.create_all(); print('DB created')"

# 5) Uygulamayı çalıştır
sudo python3 main.py

# 6) Tarayıcıda aç
# http://localhost:5000
```

### 🇬🇧 English
```bash
# 1) Install system packages
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mtr nmap

# 2) Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3) Install Python dependencies
pip install -r requirements.txt

# 4) Initialize database
python3 -c "from main import db, app; \
with app.app_context(): db.create_all(); print('DB created')"

# 5) Run the app
sudo python3 main.py

# 6) Open in browser
# http://localhost:5000
```

**Not / Note:** Bazı network araçları (örn. `scapy`, `nmap`) root yetkisi ister. Bu nedenle `sudo` ile çalıştırmanız gerekebilir. Production ortamı için `gunicorn + systemd + nginx` tavsiye edilir.  

---

## 📡 API Örneği — API Example

**Request:**
```curl
POST /api/analyze
Host: localhost:5000
Content-Type: application/json
X-API-Key: <your_api_key>

{
  "ip": "8.8.8.8"
}
```

**Response:** JSON contains fields like `ipinfo`, `whois`, `dns`, `traceroute`, `port_scan` depending on availability.  

---

## ✅ Son Söz — Final Note

- **TR:** Luminet, ağ analizi / keşif için pratik ve açık kaynaklı bir araçtır. Kullanırken yasalara ve etik kurallara uyunuz.  
- **EN:** Luminet is a practical open-source tool for network reconnaissance. Please use responsibly and comply with laws and ethical guidelines.  

---
