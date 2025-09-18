<div align="center">

# 🌐 Luminet - Open Source Network Analysis Tool
  
  <p>🌟 Star this repo if you find it useful!</p>

[![Docker Hub](https://img.shields.io/badge/Docker-Hub-blue?logo=docker)](https://hub.docker.com)
[![Hugging Face](https://img.shields.io/badge/🤗-Hugging%20Face-yellow)](https://huggingface.co/spaces/koesan/Luminet)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

https://github.com/user-attachments/assets/afa9aaf8-586a-4f67-bb67-6a3d5d13e103

[▶️ Luminet Demo Video](video/video.mp4)

## 📎 Live Demo - Canlı Demo

[![Hugging Face](https://img.shields.io/badge/🤗%20Hugging%20Face-Demo-yellow?style=for-the-badge&logo=huggingface&logoColor=white)](https://huggingface.co/spaces/koesan/Luminet)

---

🇬🇧[English](#english) | 🇹🇷[Türkçe](#türkçe)

</div>

---

## English

### 🇬🇧

## 📖 Overview

**Luminet** is a comprehensive open-source network analysis tool designed for cybersecurity professionals, network administrators, and researchers. It provides detailed reconnaissance capabilities for IP addresses and domain names using only public, free data sources.

### ✨ Key Features

- **🔍 RDAP/WHOIS Analysis** - Comprehensive registry data lookup
- **🌐 DNS Records Enumeration** - A, AAAA, MX, NS, TXT, CNAME, SOA records
- **🗺️ Geographic Location Mapping** - IP geolocation and ISP information
- **🛡️ Security Assessment** - DNSBL checks, anonymity service detection
- **🔒 SSL/TLS Certificate Analysis** - Certificate chain and security validation
- **📊 Network Routing Analysis** - Traceroute and BGP information
- **⚡ Real-time Ping Statistics** - Latency and connectivity testing
- **🔌 Port Scanning** - Open port detection and service identification

---

## 🚀 Installation & Run


```bash
# 1) Install system packages

# ------------------------------
# Debian/Ubuntu
# ------------------------------
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mtr nmap

# ------------------------------
# Fedora
# ------------------------------
sudo dnf install -y python3 python3-venv python3-pip mtr nmap

# ------------------------------
# Arch Linux / Manjaro
# ------------------------------
sudo pacman -Syu --noconfirm python python-virtualenv python-pip mtr nmap

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

**Note:** Some network tools (e.g., `scapy`, `nmap`) require root privileges. Therefore, you need to run them with `sudo`. For production environments, `gunicorn + systemd + nginx` is recommended.

---

## 📋 System Requirements

- **Python**: 3.11 or higher
- `traceroute` - Network path tracing
- `nmap` - Port scanning capabilities  
- `mtr` - Enhanced network diagnostics
- `dig`/`nslookup` - DNS utilities

---

## 🛠️ Technology Stack

### Backend
- **Framework**: Flask 2.3.3
- **Language**: Python 3.11+
- **Networking**: dnspython, requests, python-whois
- **Security**: pyOpenSSL, scapy

### Frontend
- **UI Framework**: Bootstrap 5.3.3
- **Icons**: Bootstrap Icons 1.11.3
- **Fonts**: Inter (Google Fonts)
- **Styling**: Custom CSS with CSS Grid & Flexbox

### Infrastructure
- **Process Management**: Gunicorn WSGI server
- **Health Monitoring**: Built-in health checks

---

## 🔍 Usage Examples

### Web Interface
1. Open `http://localhost:7860` in your browser
2. Enter an IP address or domain name
3. Click "Analyze" to get comprehensive results

### API Usage

```bash
# Analyze an IP address
curl -X POST http://localhost:7860/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'

# Example response
{
  "ip": "8.8.8.8",
  "ipinfo": {
    "city": "Mountain View",
    "country": "US",
    "org": "AS15169 Google LLC"
  },
  "ping": {
    "min": "10.2 ms",
    "avg": "12.5 ms",
    "max": "15.1 ms"
  }
}
```


## Türkçe

### 🇹🇷 

## 📖 Genel Bakış

**Luminet**, siber güvenlik uzmanları, ağ yöneticileri ve araştırmacılar için tasarlanmış kapsamlı bir açık kaynak ağ analiz aracıdır. Yalnızca halka açık, ücretsiz veri kaynaklarını kullanarak IP adresleri ve alan adları için detaylı keşif yetenekleri sağlar.

### ✨ Temel Özellikler

- **🔍 RDAP/WHOIS Analizi** - Kapsamlı kayıt veri arama
- **🌐 DNS Kayıt Numaralandırması** - A, AAAA, MX, NS, TXT, CNAME, SOA kayıtları
- **🗺️ Coğrafi Konum Haritalaması** - IP coğrafi konum ve ISS bilgileri
- **🛡️ Güvenlik Değerlendirmesi** - DNSBL kontrolleri, anonimlik hizmeti tespiti
- **🔒 SSL/TLS Sertifika Analizi** - Sertifika zinciri ve güvenlik doğrulaması
- **📊 Ağ Yönlendirme Analizi** - Traceroute ve BGP bilgileri
- **⚡ Gerçek Zamanlı Ping İstatistikleri** - Gecikme ve bağlanabilirlik testi
- **🔌 Port Tarama** - Açık port tespiti ve servis tanımlama

## 🚀 Kurulum & Çalıştırma 

```bash
# 1) Sistem paketlerini kur

# ------------------------------
# Debian/Ubuntu
# ------------------------------
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mtr nmap

# ------------------------------
# Fedora
# ------------------------------
sudo dnf install -y python3 python3-venv python3-pip mtr nmap

# ------------------------------
# Arch Linux / Manjaro
# ------------------------------
sudo pacman -Syu --noconfirm python python-virtualenv python-pip mtr nmap

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

**Not:** Bazı network araçları (örn. `scapy`, `nmap`) root yetkisi ister. Bu nedenle `sudo` ile çalıştırmanız gerekirr. Production ortamı için `gunicorn + systemd + nginx` tavsiye edilir.  


## 📋 Sistem Gereksinimleri

- **Python**: 3.11 veya üzeri
- `traceroute` - Ağ yolu izleme
- `nmap` - Port tarama yetenekleri
- `mtr` - Gelişmiş ağ tanılama
- `dig`/`nslookup` - DNS araçları

## 🛠️ Teknoloji Yığını

### Arka Uç
- **Framework**: Flask 2.3.3
- **Dil**: Python 3.11+
- **Ağ İletişimi**: dnspython, requests, python-whois
- **Güvenlik**: pyOpenSSL, scapy

### Ön Uç
- **UI Framework**: Bootstrap 5.3.3
- **İkonlar**: Bootstrap Icons 1.11.3
- **Yazı Tipleri**: Inter (Google Fonts)
- **Stil**: CSS Grid ve Flexbox ile özel CSS

## 🔍 Kullanım Örnekleri

### Web Arayüzü
1. Tarayıcınızda `http://localhost:7860` adresini açın
2. Bir IP adresi veya alan adı girin
3. Kapsamlı sonuçlar için "Analiz Et" düğmesine tıklayın

### API Kullanımı

```bash
# Bir IP adresini analiz etme
curl -X POST http://localhost:7860/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <p>Made with ❤️ by the Luminet community</p>
  <p>🌟 Star this repo if you find it useful!</p>
</div>
