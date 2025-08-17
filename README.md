# Luminet — Lightweight Recon Dashboard / Luminet — Hafif Keşif Panosu


https://github.com/user-attachments/assets/afa9aaf8-586a-4f67-bb67-6a3d5d13e103

[Luminet Demo](video/video.mp4)


**TR / EN (Türkçe + English)**

---

## Proje Özeti — Project Summary

**Türkçe:**  
Luminet, bir IP veya domain girildiğinde sadece açık kaynaklı, ücretsiz ve herkese açık veri kaynaklarından (WHOIS / RDAP, DNS, BGP, DNSBL, HTTP/SSL, vb.) toplanabilen bilgileri toplayıp web arayüzü üzerinden kullanıcıya sunmayı amaçlayan açık kaynaklı bir projedir. Kullanım kolaylığı, hızlı özetler ve görselleştirmeler sunar.

**English:**  
Luminet is an open-source web application that, given an IP address or domain name, aggregates publicly available information (WHOIS / RDAP, DNS, BGP, DNSBL, HTTP/SSL, etc.) and presents it through a lightweight web UI. It focuses on quick summaries, visualizations, and easy local deployment.

---

## Öne Çıkan Özellikler — Key Features

- **Türkçe:** RDAP / WHOIS özetleri, ASN ve BGP prefix ilişkileri. DNS (A/AAAA/MX/NS/TXT/CNAME/SOA), DNSSEC kontrolü ve DNSBL sorguları. Reverse-DNS, traceroute / mtr sonuçları, ping özetleri. Opsiyonel olarak `nmap` ile port taraması. HTTP header ve SSL sertifika incelemesi. Basit kullanıcı yönetimi ve API anahtarı desteği.
- **English:** RDAP / WHOIS parsing & summaries, ASN and BGP prefix mapping. DNS queries (A/AAAA/MX/NS/TXT/CNAME/SOA), DNSSEC checks, and DNSBL lookups. Reverse DNS, traceroute/mtr results and ping summaries. Optional port scanning via `nmap`. HTTP header grabs and SSL certificate analysis. Basic user management and API key support.

---

## Dosyalar / Files included
- `main.py` — Flask uygulaması (backend).  
- `index.html`, `login.html`, `register.html`, `profile.html` — temel frontend sayfaları.  
(Repo'da başka dosyalar varsa lütfen ekleyin veya güncelleyin.)

---

## Gereksinimler / Requirements

**Sistem:** Linux (Ubuntu/Debian tavsiye edilir), Python 3.10+ önerilir. `mtr` ve `nmap` gibi araçlar opsiyoneldir ama bazı özellikler için gereklidir.

Aşağıdaki `requirements.txt` dosyası pip ile kurulabilir. (Dosya yanında sunulmuştur.)

---

## Kurulum & Çalıştırma (sudo ile) — Installation & Run (with sudo)

**Türkçe adımlar:**
```bash
# 1) Sistem paketleri (örnek Ubuntu/Debian)
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mtr nmap

# 2) Repo kökünde sanal ortam oluştur (isteğe bağlı ama önerilir)
python3 -m venv .venv
source .venv/bin/activate

# 3) Python bağımlılıklarını yükle
pip install --upgrade pip
pip install -r requirements.txt

# 4) Veritabanı oluştur (ilk çalıştırma için)
python3 -c "from main import db, app; \
with app.app_context(): db.create_all(); print('DB created')"

# 5) Uygulamayı sudo ile çalıştır
sudo python3 main.py
# veya virtualenv içindeyken:
sudo -E python3 main.py

# 6) Tarayıcıda aç:
# http://localhost:5000
```

**English steps:**
```bash
# 1) System packages (example for Ubuntu/Debian)
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mtr nmap

# 2) Create virtualenv in repo root (recommended)
python3 -m venv .venv
source .venv/bin/activate

# 3) Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4) Initialize DB (first run)
python3 -c "from main import db, app; \
with app.app_context(): db.create_all(); print('DB created')"

# 5) Run app (example)
sudo python3 main.py
# or under virtualenv:
sudo -E python3 main.py

# 6) Open in browser:
# http://localhost:5000
```

**Not / Note:** Bazı network araçları (scapy, nmap) root yetkisi gerektirir; bu nedenlerle `sudo` tavsiye edilir. Production ortamı için `systemd + gunicorn + nginx` gibi yapı önerilir.

---

## Güvenlik Notları — Security Notes

- **Türkçe:** `SECRET_KEY` gibi hassas değerleri çevresel değişkenler ile sağlayın:  
  `export SECRET_KEY="$(openssl rand -hex 32)"`. Production'da `debug=False` kullanın.
- **English:** Provide secrets (e.g. `SECRET_KEY`) via environment variables. Example: `export SECRET_KEY="$(openssl rand -hex 32)"`. Do not run in debug mode in production.

API anahtarları TLS ile korunan bağlantılarda kullanılmalıdır (X-API-Key header).

---

## API Örneği — Simple API Example

**Request:**
```http
POST /api/analyze
Host: localhost:5000
Content-Type: application/json
X-API-Key: <your_api_key>

{
  "ip": "8.8.8.8"
}
```

**Response:** JSON içerisinde `ipinfo`, `whois`, `dns`, `traceroute`, `port_scan` gibi alanlar döner (kullanılabilirlik ve izinlere göre).

---

## Son Söz / Final Note

**Türkçe:** Luminet, ağ analizi / keşif amaçlı hızlı ve erişilebilir bir araç olarak tasarlandı. Kullanırken yerel kanun ve etik kurallara uyun.  
**English:** Luminet is designed as a lightweight reconnaissance dashboard for network admins and researchers. Use responsibly and comply with local laws and ethical guidelines.

---
