import os, re, time, json, socket, logging, threading, hashlib, secrets, ipaddress, subprocess, concurrent.futures, requests, pycountry, ssl
from datetime import datetime, timedelta, timezone
from functools import wraps
from collections import defaultdict, Counter
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from OpenSSL import crypto
from typing import Optional, Dict, List
import whois, tldextract
import dns.resolver, dns.reversename, dns.message, dns.query, dns.rdatatype, dns.flags, dns.edns, dns.zone
from dns.resolver import NoAnswer, NXDOMAIN, Timeout, NoNameservers, YXDOMAIN
from dns.exception import DNSException
from dns.query import BadResponse

# Opsiyonel bağımlılıklar için import denemeleri
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except (ImportError, PermissionError):
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Flask uygulaması ve konfigürasyon
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.jinja_env.globals.update(json=json)
app.jinja_env.filters['tojson'] = json.dumps

# Veritabanı ve kimlik yönetimi
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Loglama konfigürasyonu
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Kullanıcı yükleme fonksiyonu - EKSİK OLAN KISIM EKLENDİ
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# API endpointleri
IANA_IP_BOOTSTRAP_URL = "https://rdap.iana.org/ip/"
IANA_ASN_BOOTSTRAP_URL = "https://rdap.iana.org/autnum/"
RIPESTAT_DATA_URL = "https://stat.ripe.net/data/"
IPINFO_URL = "https://ipinfo.io/"
IP_API_URL = "http://ip-api.com/json/" # Keep this, as other parts of the code use it.
OSM_NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"

# Traceroute için API rate limitini göz önünde bulundur
REQUEST_DELAY = 0.1 # Saniye başına gecikme (ip-api.com için önerilen 15 istek/dakika)

# Veritabanı modelleri
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    api_key = db.Column(db.String(32), unique=True, nullable=False)
    activities = db.relationship('ActivityLog', backref='user', lazy=True)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    search_term = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    source = db.Column(db.String(10))

# DNSBL listeleri
DNS_BL_LISTS = {
    'spam': {
        'zen.spamhaus.org': 'Spamhaus Zen (SBL+XBL+PBL)',
        'bl.spamcop.net': 'SpamCop Blocking List',
        'bl.spameatingmonkey.net': 'SEM Black',
        'backscatter.spameatingmonkey.net': 'SEM Backscatter',
        'bl.mailspike.net': 'Mailspike',
        'bl.drmx.org': 'DRMX',
        'bl.0spam.org': '0Spam Main BL',
        'rbl.0spam.org': '0Spam Realtime BL',
        'bl.nordspam.com': 'NordSpam IP BL',
    },

    'domain': {
        'dbl.0spam.org': '0Spam Domain BL',
        'dbl.nordspam.com': 'NordSpam Domain BL',
        'uribl.spameatingmonkey.net': 'SEM URI BL',
        'urired.spameatingmonkey.net': 'SEM URI Red',
    },

    'network': {
        'b.barracudacentral.org': 'Barracuda Reputation Block List',
        'dnsbl.sorbs.net': 'SORBS Aggregate',
        'dnsbl-1.uceprotect.net': 'UCEPROTECT Level 1',
        'dnsbl-2.uceprotect.net': 'UCEPROTECT Level 2',
        'dnsbl-3.uceprotect.net': 'UCEPROTECT Level 3',
        'dyna.spamrats.com': 'SpamRats Dynamic IP List',
        'noptr.spamrats.com': 'SpamRats NoPTR List',
        'netbl.spameatingmonkey.net': 'SEM Network BL',
        'bl.ipv6.spameatingmonkey.net': 'SEM IPv6 BL',
        'nbl.0spam.org': '0Spam Network BL',
    },

    'proxy_bot': {
        'dnsbl.dronebl.org': 'DroneBL',
        'tor.dan.me.uk': 'Tor Exit Nodes',
        'torexit.dan.me.uk': 'Tor Exit Nodes Only',
        'openproxy.bls.digibase.ca': 'Digibase OpenProxy',
        'proxyabuse.bls.digibase.ca': 'Digibase Proxy Abuse',
        'spambot.bls.digibase.ca': 'Digibase Spambot',
        'socks.dnsbl.sorbs.net': 'SORBS SOCKS Proxies',
        'zombie.dnsbl.sorbs.net': 'SORBS Zombies',
    },

    'misc': {
        'psbl.surriel.com': 'Passive Spam Block List',
        'db.wpbl.info': 'Weighted Private Block List',
        'bl.blocklist.de': 'Blocklist.de',
        'all.s5h.net': 'S5H Blocklist',
        'rbl.efnet.org': 'EFNet RBL',
        'combined.rbl.msrbl.net': 'MSRBL Combined',
        'bl.mxrbl.com': 'MXRBL',
    },
}
def get_dns_records(domain):
    records = {
        "A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": None, "SOA": None,
        "SRV": [], "CAA": [], "DMARC": [], "SPF": [], "PTR": [], "NAPTR": [], "SSHFP": [],
        "TLSA": [], "LOC": [], "DS": [], "DNSKEY": [], "WHOIS": {}, "ZONE_TRANSFER": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # A
    for rdata in safe_resolve(resolver, domain, 'A'):
        records["A"].append(rdata.address)

    # AAAA
    for rdata in safe_resolve(resolver, domain, 'AAAA'):
        records["AAAA"].append(rdata.address)

    # PTR
    for ip_addr in records["A"] + records["AAAA"]:
        try:
            rev_name = dns.reversename.from_address(ip_addr)
            for rdata in safe_resolve(resolver, rev_name, 'PTR'):
                records["PTR"].append({"ip": ip_addr, "ptr": str(rdata.target)})
        except Exception:
            pass

    # MX
    for rdata in safe_resolve(resolver, domain, 'MX'):
        records["MX"].append({"preference": rdata.preference, "exchange": rdata.exchange.to_text()})

    # TXT / SPF
    for rdata in safe_resolve(resolver, domain, 'TXT'):
        for txt_string in rdata.strings:
            txt_record = txt_string.decode('utf-8')
            records["TXT"].append(txt_record)
            if txt_record.lower().startswith('v=spf'):
                records["SPF"].append(txt_record)

    # DMARC
    for rdata in safe_resolve(resolver, f'_dmarc.{domain}', 'TXT'):
        for txt_string in rdata.strings:
            records["DMARC"].append(txt_string.decode('utf-8'))

    # NS
    for rdata in safe_resolve(resolver, domain, 'NS'):
        records["NS"].append(rdata.target.to_text())

    # CNAME
    cname_result = safe_resolve(resolver, domain, 'CNAME')
    if cname_result:
        records["CNAME"] = cname_result[0].target.to_text()

    # SOA
    soa_result = safe_resolve(resolver, domain, 'SOA')
    if soa_result:
        soa = soa_result[0]
        records["SOA"] = {
            "mname": soa.mname.to_text(),
            "rname": soa.rname.to_text(),
            "serial": soa.serial,
            "refresh": soa.refresh,
            "retry": soa.retry,
            "expire": soa.expire,
            "minimum": soa.minimum
        }

    # SRV
    for rdata in safe_resolve(resolver, domain, 'SRV'):
        records["SRV"].append({
            "port": rdata.port,
            "target": rdata.target.to_text(),
            "priority": rdata.priority,
            "weight": rdata.weight
        })

    # CAA
    for rdata in safe_resolve(resolver, domain, 'CAA'):
        records["CAA"].append({
            "flags": rdata.flags,
            "tag": rdata.tag.decode('utf-8'),
            "value": rdata.value.decode('utf-8')
        })

    # Ek kayıtlar
    for rdata in safe_resolve(resolver, domain, 'NAPTR'):
        records["NAPTR"].append(str(rdata))

    for rdata in safe_resolve(resolver, domain, 'SSHFP'):
        records["SSHFP"].append(str(rdata))

    for rdata in safe_resolve(resolver, domain, 'TLSA'):
        records["TLSA"].append(str(rdata))

    for rdata in safe_resolve(resolver, domain, 'LOC'):
        records["LOC"].append(str(rdata))

    for rdata in safe_resolve(resolver, domain, 'DS'):
        records["DS"].append(str(rdata))

    for rdata in safe_resolve(resolver, domain, 'DNSKEY'):
        records["DNSKEY"].append(str(rdata))

    # WHOIS - sadece gerçek domainlerde çalıştır
    try:
        extracted = tldextract.extract(domain)
        real_domain = f"{extracted.domain}.{extracted.suffix}"
        w = whois.whois(real_domain)
        records["WHOIS"] = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails
        }
    except Exception as e:
        records["WHOIS"] = {"error": str(e)}

    # Zone transfer testi
    try:
        ns_records = safe_resolve(resolver, domain, 'NS')
        for ns in ns_records:
            try:
                ns_ip = safe_resolve(resolver, ns.target, 'A')[0].to_text()
                xfr = dns.query.xfr(ns_ip, domain, timeout=5)
                zone = dns.zone.from_xfr(xfr)
                records["ZONE_TRANSFER"] = list(zone.nodes.keys())
            except Exception:
                pass
    except Exception:
        pass

    return records

def whois_info(domain):
    try:
        extracted = tldextract.extract(domain)
        real_domain = f"{extracted.domain}.{extracted.suffix}"
        w = whois.whois(real_domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails
        }
    except Exception as e:
        return {"error": str(e)}

print(whois_info("google.com"))

def safe_resolve(resolver, qname, rdtype):
    try:
        return resolver.resolve(qname, rdtype, raise_on_no_answer=False)
    except (NoAnswer, NXDOMAIN, Timeout, NoNameservers, DNSException):
        return []

def get_authoritative_dns(domain):
    """Gerçek alan adının yetkili DNS sunucusunu bulur."""
    try:
        ns_to_query = '198.41.0.4'  # Root server
        parts = domain.split('.')
        for i in range(len(parts)):
            subdomain = '.'.join(parts[i:])
            q = dns.message.make_query(subdomain, dns.rdatatype.NS)
            res = dns.query.udp(q, ns_to_query, timeout=5)
            if res.authority:
                ns_record = res.authority[0]
                return str(ns_record[0].target)
            elif res.additional:
                for rdata in res.additional:
                    if rdata.rdtype == dns.rdatatype.A:
                        ns_to_query = rdata.address
                        break
    except Exception:
        pass
    return None

def check_dnssec(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.use_edns(edns=True, payload=4096)
        ds_records = resolver.resolve(domain, 'DS', raise_on_no_answer=False)
        dnskey_records = resolver.resolve(domain, 'DNSKEY', raise_on_no_answer=False)
        if ds_records and dnskey_records:
            return "DNSSEC Etkin (DS ve DNSKEY kayıtları bulundu)"
        elif ds_records:
            return "DNSSEC Kısmen Etkin (Sadece DS kaydı bulundu)"
        else:
            return "DNSSEC Etkin Değil"
    except (NoAnswer, NXDOMAIN, Timeout, NoNameservers):
        return "DNSSEC Durumu Belirlenemedi"
    except Exception as e:
        return f"Hata: {str(e)}"



def check_dnsbl(ip_address):
    results = defaultdict(list)
    results_lock = threading.Lock()
    
    try:
        if '.' in ip_address:
            reversed_ip = '.'.join(reversed(ip_address.split('.')))
        else:
            reversed_ip = dns.reversename.from_address(ip_address).to_text(omit_final_dot=True).replace('.ip6.arpa', '')
    except Exception as e:
        results['error'] = f"IP adresi çevrim hatası: {str(e)}"
        return results

    def query_worker(dnsbl, description, category):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            resolver.timeout = 5
            resolver.lifetime = 5

            query = f"{reversed_ip}.{dnsbl}"
            answers = resolver.resolve(query, 'A')
            
            for answer in answers:
                with results_lock:
                    results[category].append({
                        'dnsbl': dnsbl,
                        'description': description,
                        'response': answer.to_text()
                    })
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.resolver.Timeout:
            with results_lock:
                results[category].append({'dnsbl': dnsbl, 'error': 'Timeout'})
        except Exception as e:
            with results_lock:
                results[category].append({'dnsbl': dnsbl, 'error': str(e)})

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_dnsbl = {
            executor.submit(query_worker, dnsbl, description, category): dnsbl
            for category, blacklists in DNS_BL_LISTS.items()
            for dnsbl, description in blacklists.items()
        }
        
        for future in concurrent.futures.as_completed(future_to_dnsbl):
            try:
                future.result()
            except Exception as exc:
                dnsbl_name = future_to_dnsbl[future]
                logger.error(f'{dnsbl_name} sorgusunda beklenmedik hata oluştu: {exc}')

    return results

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key is missing'}), 401
            
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
            
        return f(user, *args, **kwargs)
    return decorated_function

def cleanup_old_logs():
    with app.app_context():
        try:
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            db.session.query(ActivityLog).filter(ActivityLog.timestamp < seven_days_ago).delete()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Log cleanup error: {str(e)}")

scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_old_logs, trigger="interval", hours=1)
scheduler.start()

def process_bgp_data_for_d3(bgp_data, target_asn_str=None):
    if not bgp_data or 'bgp_state' not in bgp_data or not bgp_data['bgp_state']:
        return None

    def get_color_for_path(path):
        key = '-'.join(map(str, path))
        hash_digest = hashlib.md5(key.encode()).hexdigest()
        return f"#{hash_digest[:6]}"

    def get_color_for_asn(asn):
        key = str(asn)
        hash_digest = hashlib.md5(key.encode()).hexdigest()
        return f"#{hash_digest[6:12]}"

    nodes = {}
    raw_links = []
    source_asns = set()
    target_asn = int(target_asn_str) if target_asn_str and target_asn_str.isdigit() else None

    for entry in bgp_data.get('bgp_state', []):
        path = entry.get('path', [])
        if not path:
            continue

        source_asns.add(path[0])
        path_color = get_color_for_path(path) 

        path_details = {
            "community": entry.get("community", []),
            "full_path": entry.get("path", []),
            "source_id": entry.get("source_id", "Bilinmiyor"),
            "target_prefix": entry.get("target_prefix", "Bilinmiyor")
        }

        for asn in path:
            if asn not in nodes:
                nodes[asn] = {"id": str(asn), "label": f"AS{asn}", "color": get_color_for_asn(asn), "node_type": "transit"}

        for i in range(len(path) - 1):
            link_data = {
                "source": str(path[i]),
                "target": str(path[i+1]),
                "color": path_color, 
                **path_details
            }
            raw_links.append(link_data)

    for asn, node_data in nodes.items():
        if asn == target_asn:
            node_data["type"] = "target" 
        elif asn in source_asns:
            node_data["type"] = "source" 
    if not raw_links:
        return None

    link_counts = defaultdict(int)
    for link in raw_links:
        key = tuple(sorted((link['source'], link['target'])))
        link_counts[key] += 1

    processed_links = []
    link_group_indices = defaultdict(int)
    for link in raw_links:
        key = tuple(sorted((link['source'], link['target'])))
        total_links_in_group = link_counts[key]
        new_link = link.copy()
        new_link['total_links'] = total_links_in_group
        new_link['link_index'] = link_group_indices[key]
        processed_links.append(new_link)
        link_group_indices[key] += 1

    return {"nodes": list(nodes.values()), "links": processed_links}
    
def get_country_name(code: str) -> str:
    try:
        country = pycountry.countries.get(alpha_2=code.upper())
        return country.name if country else "Bilinmeyen Ülke"
    except Exception as e:
        logger.error(f"Ülke ismi alınamadı: {str(e)}")
        return "Geçersiz Kod"

def get_reverse_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "PTR kaydı bulunamadı"
    except Exception as e:
        logger.error(f"Reverse DNS hatası: {str(e)}")
        return f"Hata: {str(e)}"

def get_ping_latency(ip, packet_count=4):

    try:
        command = ["ping", "-c", str(packet_count), ip] if os.name != "nt" else ["ping", "-n", str(packet_count), ip]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0:
            output = result.stdout
            
            if os.name != "nt": 
                match = re.search(r"rtt en düşük/ortalama/en yüksek/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", output)
                if match:
                    return {
                        "min": f"{match.group(1)} ms",
                        "avg": f"{match.group(2)} ms",
                        "max": f"{match.group(3)} ms",
                        "mdev": f"{match.group(4)} ms"
                    }
            else: 
                match = re.search(r"Minimum = (\d+ms), Maximum = (\d+ms), Average = (\d+ms)", output)
                if match:
                    return {
                        "min": match.group(1),
                        "max": match.group(2),
                        "avg": match.group(3)
                    }
            
            return {"error": "Ping sonuçları regex ile eşleşmedi", "raw": output}
        else:
            return {"error": f"Ping komutu hata kodu döndürdü ({result.returncode}): {result.stderr or result.stdout}", "raw": result.stdout + result.stderr}
    except FileNotFoundError:
        return {"error": "Ping komutu bulunamadı. PATH ayarınızı veya komutun konumunu kontrol edin."}
    except subprocess.TimeoutExpired:
        return {"error": "Ping isteği zaman aşımına uğradı"}
    except Exception as e:
        return {"error": f"Beklenmedik hata: {str(e)}"}

def scan_ports(ip):
    if not NMAP_AVAILABLE:
        return {"error": "Nmap kütüphanesi kurulu değil"}
    
    try:
        nm = nmap.PortScanner()
        
        common_ports = (
            "1-1024,1433-1434,1521,1720-1723,2049,2375-2379,3306,3389,"
            "5000-5010,5432,5900-5905,6379,8080,8443,9000-9100,69,"
            "161-162,2222,5601,9200-9300,27017,11211,10000,"
            "8000-8010,8081,8082,8888,4848,9001,8086,9418,25,"
            "110,143,993,995,514,1812-1813,2376,2377,4789,"
            "10050-10051,9100,5984"
        )
        
        scan_results = nm.scan(
            hosts=ip, 
            arguments=f'-T4 -Pn -p {common_ports}'
        )
        
        open_ports = []
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    port_info = nm[ip][proto][port]
                    if port_info['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'state': port_info['state'],
                            'name': port_info.get('name', 'bilinmiyor'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                        })
        return {"ports": open_ports}
    
    except nmap.PortScannerError as e:
        logger.error(f"Nmap hatası: {str(e)}")
        return {"error": f"Nmap hatası: {str(e)}"}
    except Exception as e:
        logger.error(f"Port tarama hatası: {str(e)}")
        return {"error": f"Port tarama hatası: {str(e)}"}

def get_http_headers(host):
    urls = [f"https://{host}", f"http://{host}"]
    headers = {'User-Agent': 'GlobalIPASNTool/1.0 (Mozilla/5.0)'}
    last_error = None  

    for url in urls:
        try:
            response = requests.get(
                url, 
                headers=headers, 
                timeout=10, 
                allow_redirects=True, 
                verify=False
            )
            
            history_data = []
            for h in response.history:
                history_item = {
                    "url": h.url,
                    "status_code": h.status_code,
                    "headers": dict(h.headers)
                }
                history_data.append(history_item)
            
            return {
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "history": history_data
            }
        except requests.exceptions.RequestException as e:
            last_error = e  
            logger.warning(f"HTTP başlık hatası: {str(e)}")
            continue
    
    return {"error": f"HTTP/HTTPS bağlantısı kurulamadı: {str(last_error)}"}

def is_public_ip(ip: str) -> bool:
    """Check if an IP address is public/routable."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or 
                    ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified)
    except ValueError:
        return False

# --- Modified get_location to match the provided standalone version for richer data ---
def get_location(ip: str) -> Optional[Dict]:
    """Get geolocation information for an IP address."""
    if not is_public_ip(ip):
        return None
    
    try:
        response = requests.get(
            f"{IP_API_URL}{ip}",
            params={"fields": "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "continent": data.get("continent", ""),
                    "continent_code": data.get("continentCode", ""),
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "country_name": get_country_name(data.get("countryCode", "")),
                    "region": data.get("region", ""),
                    "region_name": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "district": data.get("district", ""),
                    "zip": data.get("zip", ""),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone", ""),
                    "offset": data.get("offset", ""),
                    "currency": data.get("currency", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as_number": data.get("as", ""),
                    "as_name": data.get("asname", ""),
                    "reverse_dns": data.get("reverse", ""),
                    "mobile": data.get("mobile", False),
                    "proxy": data.get("proxy", False),
                    "hosting": data.get("hosting", False),
                }
        logger.warning(f"Location lookup failed for {ip}: {data.get('message', 'Unknown error')}")
        return None
    except Exception as e:
        logger.error(f"Failed to get location for {ip}: {str(e)}")
        return None

def get_locations_batch(ips: List[str]) -> List[Optional[Dict]]:
    """Batch geolocation lookup for multiple IPs."""
    if not ips:
        return []
    
    public_ips = [ip for ip in ips if is_public_ip(ip)]
    if not public_ips:
        return [None] * len(ips)
    
    try:
        response = requests.post(
            "http://ip-api.com/batch",
            json=[{"query": ip, "fields": "status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query"} 
                  for ip in public_ips],
            timeout=10
        )
        
        if response.status_code == 200:
            results = response.json()
            # Map results back to original IP list
            result_map = {result["query"]: result for result in results if result.get("status") == "success"}
            locations = []
            for ip in ips:
                if ip in result_map:
                    data = result_map[ip]
                    locations.append({
                        "ip": ip,
                        "lat": data["lat"],
                        "lon": data["lon"],
                        "city": data.get("city", ""),
                        "country": data.get("country", ""),
                        "country_name": get_country_name(data.get("countryCode", "")),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "as_number": data.get("as", ""),
                        "as_name": data.get("asname", ""),
                    })
                else:
                    locations.append(None)
            return locations
    except Exception as e:
        logger.error(f"Batch location lookup failed: {str(e)}")
    
    # Fallback to individual lookups if batch fails
    return [get_location(ip) if is_public_ip(ip) else None for ip in ips]

def system_traceroute(ip: str, max_hops: int = 30, timeout: int = 60) -> List[Dict]:
    """Perform a system traceroute and return hops."""
    # Determine OS and appropriate command
    if os.name == "nt":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", ip]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", ip]
    
    try:
        proc = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            check=True
        )
        
        hops = []
        ttl = 1
        
        for line in proc.stdout.splitlines():
            # Skip header lines
            if not line.strip() or line.startswith(("traceroute", "tracert", "Tracing")):
                continue
                
            # Parse line based on OS
            if os.name == "nt":
                # Windows tracert format
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1].replace(".", "").isdigit():
                    hop_ip = parts[1]
                    hops.append({"ip": hop_ip, "ttl": ttl})
                    ttl += 1
            else:
                # Unix traceroute format
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] != "*":
                    hop_ip = parts[1]
                    # Handle cases where IP is in parentheses
                    if "(" in hop_ip and ")" in hop_ip:
                        hop_ip = hop_ip[hop_ip.find("(")+1:hop_ip.find(")")]
                    hops.append({"ip": hop_ip, "ttl": ttl})
                    ttl += 1
        
        return hops
    
    except subprocess.TimeoutExpired:
        logger.warning(f"Traceroute timed out after {timeout} seconds")
        return []
    except subprocess.CalledProcessError as e:
        logger.error(f"Traceroute failed with error: {e.stderr}")
        return []
    except Exception as e:
        logger.error(f"Unexpected traceroute error: {str(e)}")
        return []

def enriched_traceroute(target_ip: str, max_hops: int = 30) -> List[Dict]:
    """Perform traceroute with geolocation information for each hop."""
    # First get all hops
    hops = system_traceroute(target_ip, max_hops=max_hops)
    
    if not hops:
        return []
    
    # Extract IPs for batch lookup
    hop_ips = [hop["ip"] for hop in hops]
    
    # Get locations in batch if possible
    locations = get_locations_batch(hop_ips)
    
    # Enrich hop data with location information
    enriched_hops = []
    for hop, location in zip(hops, locations):
        enriched_hop = {
            "ip": hop["ip"],
            "ttl": hop["ttl"],
            "location": location
        }
        enriched_hops.append(enriched_hop)
        
        # Respect rate limits
        # No need for individual sleep here if using batch,
        # but if get_locations_batch falls back to individual calls,
        # the internal logic of get_locations_batch should handle delays.
        # For simplicity, remove time.sleep here since get_locations_batch handles it.
        # if len(enriched_hops) % 10 == 0:
        #    time.sleep(REQUEST_DELAY)
    
    return enriched_hops


def get_asn_from_ip(ip):
    try:
        r = requests.get(f"{RIPESTAT_DATA_URL}prefix-overview/data.json?resource={ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            asns = data.get("data", {}).get("asns", [])
            if asns:
                return str(asns[0]["asn"])
        return None
    except Exception as e:
        logger.error(f"ASN alınamadı: {str(e)}")
        return None

def get_asn_path_locations(asn):
    try:
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            prefixes = data.get("data", {}).get("ipv4_prefixes", []) + data.get("data", {}).get("ipv6_prefixes", [])
            countries = [p.get("country_code") for p in prefixes if p.get("country_code")]
            return Counter(countries)
        return Counter()
    except Exception as e:
        logger.error(f"BGPView ASN path hatası: {str(e)}")
        return Counter()

def lookup_coords_osm(country_code):
    try:
        if not country_code:
            return None, None
            
        country_name = get_country_name(country_code)
        if not country_name:
            return None, None
            
        params = {"q": country_name, "format": "json", "limit": 1}
        headers = {"User-Agent": "GlobalIPASNTool/1.0"}
        r = requests.get(OSM_NOMINATIM_URL, params=params, headers=headers, timeout=5)
        r.raise_for_status()
        results = r.json()
        if results:
            return float(results[0]["lat"]), float(results[0]["lon"])
        return None, None
    except Exception as e:
        logger.error(f"[OSM Lookup Hatası] {country_code}: {str(e)}")
        return None, None

def get_asn_map_data(ip):
    asn = get_asn_from_ip(ip)
    if not asn:
        return (None, [])
    
    location_counts = get_asn_path_locations(asn)
    map_points = []
    
    for country_code, count in location_counts.most_common(15):
        lat, lon = lookup_coords_osm(country_code)
        if lat and lon:
            map_points.append({
                "loc": country_code, 
                "count": count, 
                "lat": lat, 
                "lon": lon,
                "country_name": get_country_name(country_code)
            })
    
    return (asn, map_points)

def parse_vcard(vcard_array):
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return {}
    
    vcard_data = vcard_array[1]
    contact = {
        "name": "Bilinmiyor", 
        "org": "Bilinmiyor", 
        "email": "Bilinmiyor", 
        "address": "Bilinmiyor", 
        "tel": "Bilinmiyor"
    }
    
    for item in vcard_data:
        if len(item) < 4:
            continue
            
        prop, params, p_type, value = item[0], item[1], item[2], item[3]
        if prop == "fn": 
            contact["name"] = value
        elif prop == "org": 
            contact["org"] = value
        elif prop == "email": 
            contact["email"] = value
        elif prop == "tel": 
            contact["tel"] = value
        elif prop == "adr":
            address_label = params.get("label", "")
            if address_label:
                contact["address"] = address_label.replace("\r\n", ", ").replace("\n", ", ")
            elif isinstance(value, list):
                contact["address"] = ", ".join(filter(None, value))
    
    return contact

def run_mtr_analysis(ip):
    if not ip or not isinstance(ip, str):
        return {"error": "Geçersiz IP adresi veya hostname."}
    
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        pass 
    
    command = [
        "sudo", "mtr", 
        "-r",           
        "-c", "10",     
        "--json",       
        ip              
    ]
    
    result = {"ip": ip, "timestamp": datetime.now().isoformat()}
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1 
        )
        
        stdout, stderr = process.communicate(timeout=60)
        
        if process.returncode != 0:
            error_msg = stderr.strip()
            if "Name or service not known" in error_msg or "Temporary failure in name resolution" in error_msg:
                user_error = f"Hedef hostname çözümlenemedi: {ip}. Lütfen doğru bir IP veya hostname girin."
            elif "No such device" in error_msg or "Cannot find device" in error_msg:
                user_error = "Ağ arayüzü hatası: MTR gerekli ağ cihazını bulamadı."
            elif "Operation not permitted" in error_msg or "Permission denied" in error_msg:
                user_error = "İzin hatası: MTR çalıştırmak için 'sudo' yetkisi gerekli. Lütfen sunucunuzda MTR'ın düzgün kurulduğundan ve izinlerinin doğru olduğundan emin olun."
            else:
                user_error = "MTR analizi başarısız oldu."
            
            logger.error(f"MTR command failed for {ip}: {error_msg} (Exit code: {process.returncode})")
            result.update({
                "error": user_error,
                "details": error_msg,
                "raw_output": stdout,
                "raw_error": stderr
            })
            return result
            
        if not stdout.strip(): 
            logger.error(f"MTR returned empty output for {ip}.")
            result["error"] = "MTR boş sonuç döndürdü. Hedef erişilemiyor olabilir veya MTR çıktısı beklenenden farklı."
            result["raw_output"] = stdout
            result["raw_error"] = stderr
            return result
            
        try:
            mtr_data = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.error(f"MTR JSON decoding error for {ip}: {e}. Raw stdout: {stdout}")
            result.update({
                "error": "MTR çıktısı çözümlenemedi. Biçim hatası.",
                "details": f"JSON çözümleme hatası: {e}",
                "raw_output": stdout,
                "raw_error": stderr
            })
            return result

        report = mtr_data.get('report', {})
        hubs = report.get('hubs', [])
        
        cleaned_hops = []
        for idx, hop in enumerate(hubs, 1):
            host = hop.get('host', '???').strip() 
            
            is_private = False
            try:
                if host != '???':
                    ip_obj = ipaddress.ip_address(host)
                    is_private = ip_obj.is_private
            except ValueError:
                pass
            
            loss = float(hop.get('Loss%', 0.0))
            avg = float(hop.get('Avg', 0.0))
            best = float(hop.get('Best', 0.0))
            worst = float(hop.get('Worst', 0.0))
            last = float(hop.get('Last', 0.0))
            snt = int(hop.get('Snt', 0)) 

            cleaned_hops.append({
                'count': idx,
                'host': host,
                'loss': loss,
                'avg': avg,
                'best': best,
                'worst': worst,
                'last': last,
                'is_private': is_private,
                'packets_sent': snt
            })
        
        overall_packet_loss = float(report.get('loss', 0.0))
        if not hubs and overall_packet_loss == 0.0 and snt == 0: 
            overall_packet_loss = 100.0 if "No route to host" in stderr or "Host unreachable" in stderr else 0.0
        
        result.update({
            "hops": cleaned_hops,
            "destination": report.get('dst', ip).strip(),
            "packet_loss": overall_packet_loss,
            "total_hops": len(cleaned_hops)
        })
        
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate() 
        error_msg = f"MTR analizi zaman aşımına uğradı ({ip})"
        logger.error(error_msg)
        result.update({
            "error": "MTR analizi zaman aşımına uğradı. Hedefe ulaşmak çok uzun sürdü veya ağ engellendi.",
            "details": "Analiz 60 saniyeden uzun sürdü.",
            "raw_output": stdout,
            "raw_error": stderr
        })
        
    except FileNotFoundError:
        logger.error("MTR komutu bulunamadı. Lütfen sisteminizde 'mtr' yüklü olduğundan emin olun.")
        result.update({
            "error": "MTR komutu bulunamadı. Sunucuda 'mtr' kurulu değil.",
            "details": "Lütfen sunucunuzda 'sudo apt-get install mtr' veya benzeri komutla MTR'ı kurun."
        })
    except PermissionError as e:
        logger.error(f"MTR çalıştırmak için izin hatası: {e}")
        result.update({
            "error": "MTR çalıştırmak için yetki hatası.",
            "details": f"MTR komutunu çalıştırmak için gerekli izinler yok. Hata: {e}. 'sudo' yapılandırmanızı kontrol edin."
        })
    except Exception as e:
        logger.error(f"MTR beklenmedik hata için {ip}: {e}")
        result.update({
            "error": "Beklenmedik bir hata oluştu.",
            "details": str(e)
        })
        
    return result

def get_bgpview_prefix_details(ip):
    """
    BGPView API'sini kullanarak bir IP adresinin ait olduğu prefix hakkında
    detaylı bilgi alır (prefix, isim, açıklama, ülke).
    """
    try:
        url = f"https://api.bgpview.io/ip/{ip}"
        response = robust_get_request(url, timeout=5)
        if response and response.status_code == 200:
            data = response.json().get("data", {})
            # Birden fazla prefix olabilir, en spesifik olanı (en uzun) alalım.
            longest_prefix = max(data.get("prefixes", []), key=lambda p: p.get("prefix", "").split('/')[1], default=None)
            if longest_prefix:
                return {
                    "prefix": longest_prefix.get("prefix"),
                    "name": longest_prefix.get("name"),
                    "description": longest_prefix.get("description"),
                    "country_code": longest_prefix.get("country_code")
                }
        return None
    except Exception as e:
        logger.error(f"BGPView prefix detayları alınamadı: {str(e)}")
        return None

def get_peeringdb_info(asn):
    """
    PeeringDB API'sini kullanarak bir ASN hakkında temel bilgileri
    (isim, web sitesi, trafik türü, anons edilen prefix sayısı) alır.
    """
    if not asn:
        return None
    try:
        url = f"https://www.peeringdb.com/api/net?asn={asn}"
        response = robust_get_request(url, timeout=7)
        if response and response.status_code == 200:
            data = response.json().get("data", [])
            if data:
                net_info = data[0]
                return {
                    "name": net_info.get("name"),
                    "website": net_info.get("website"),
                    "traffic_type": net_info.get("info_traffic"),
                    "prefix_count_ipv4": net_info.get("info_prefixes4"),
                    "prefix_count_ipv6": net_info.get("info_prefixes6"),
                    "policy": net_info.get("policy_general")
                }
        return None
    except Exception as e:
        logger.error(f"PeeringDB bilgisi alınamadı: {str(e)}")
        return None
def parse_rdap_response(data):
    """
    Ham RDAP JSON yanıtını ayrıştırarak ön yüzde kullanılacak
    yapılandırılmış bir sözlük oluşturur.
    """
    parsed_info = {
        "summary": {},
        "contacts": {
            "abuse": [], 
            "technical": [], 
            "administrative": [], 
            "registrant": [], 
            "other": []
        },
        "details": {}, # Olaylar ve notlar gibi ek bilgiler bu sözlükte toplanır
        "source_rir": "Bilinmiyor",
    }
    
    # RIR kaynağını (RIPE, ARIN vb.) belirle
    if "port43" in data:
        port43_val = data["port43"].lower()
        rir_mapping = {
            "apnic": "APNIC", "lacnic": "LACNIC", "afrinic": "AfriNIC", 
            "arin": "ARIN", "ripe": "RIPE NCC",
        }
        parsed_info["source_rir"] = next((v for k, v in rir_mapping.items() if k in port43_val), "Bilinmiyor")

    # Temel özet bilgileri
    summary = {
        "name": data.get("name", "Bilinmiyor"), 
        "handle": data.get("handle", "Bilinmiyor"), 
        "country": data.get("country", "Bilinmiyor"),
        "ip_range": f"{data.get('startAddress', '')} - {data.get('endAddress', '')}",
        "asn_range": f"{data.get('startAutnum', '')} - {data.get('endAutnum', '')}",
        "type": data.get("type", "Bilinmiyor").title(),
    }
    if summary["ip_range"] == " - ": summary.pop("ip_range", None)
    if summary["asn_range"] == " - ": summary.pop("asn_range", None)
    parsed_info["summary"] = summary

    # İletişim bilgilerini ayrıştır
    for entity in data.get("entities", []):
        vcard_array = entity.get("vcardArray")
        if not vcard_array:
            continue
        contact_details = parse_vcard(vcard_array)
        roles = entity.get("roles", [])
        
        # Rolleri uygun kategorilere ata
        assigned = False
        for role in ["registrant", "administrative", "technical", "abuse"]:
            if role in roles:
                parsed_info["contacts"][role].append(contact_details)
                assigned = True
        if not assigned:
            parsed_info["contacts"]["other"].append(contact_details)

    # ---> YENİ EKLENEN DETAYLARIN TOPLANDIĞI KISIM <---
    # 'events' (tarihler) ve 'remarks' (notlar) gibi daha derinlemesine
    # bilgileri 'details' anahtarı altında sakla.
    parsed_info["details"] = {
        "events": data.get("events", []), 
        "remarks": data.get("remarks", []),
        "links": data.get("links", []), 
        "notices": data.get("notices", []),
        "object_class_name": data.get("objectClassName", "Bilinmiyor"),
    }
    
    return parsed_info


def get_authoritative_rdap_url(query):
    query = query.strip().upper().replace("AS", "")
    is_ip = "." in query or ":" in query
    rdap_type = "ip" if is_ip else "autnum"
    bootstrap_url = IANA_IP_BOOTSTRAP_URL if is_ip else IANA_ASN_BOOTSTRAP_URL

    try:
        r = robust_get_request(f"{bootstrap_url}{query}", timeout=10, headers={"Accept": "application/rdap+json"})
        if r.status_code == 501:
            raise requests.exceptions.HTTPError("IANA RDAP not implemented", response=r)

        r.raise_for_status()
        iana_data = r.json()
        for link in iana_data.get("links", []):
            if link.get("rel") == "related":
                return link.get("href")
        logger.warning("IANA RDAP sonucu var ama yönlendirme linki bulunamadı.")
    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 501:
            logger.warning(f"IANA RDAP not implemented, trying fallback RIRs")
        else:
            logger.warning(f"IANA RDAP URL alınamadı: {str(http_err)}")
    except requests.exceptions.RequestException as e:
        logger.warning(f"IANA RDAP bağlantısı başarısız: {str(e)}")

    fallback_rir_urls = {
        "ripe":    f"https://rdap.db.ripe.net/{rdap_type}/{query}",
        "apnic":   f"https://rdap.apnic.net/{rdap_type}/{query}",
        "lacnic":  f"https://rdap.lacnic.net/rdap/{rdap_type}/{query}",
        "afrinic": f"https://rdap.afrinic.net/rdap/{rdap_type}/{query}",
        "arin":    f"https://rdap.arin.net/registry/{rdap_type}/{query}"
    }

    for rir, url in fallback_rir_urls.items():
        try:
            r = robust_get_request(url, timeout=10, headers={"Accept": "application/rdap+json"}) 
            if r.status_code == 200:
                logger.info(f"{rir.upper()} RDAP kaynağı kullanıldı: {url}")
                return url
        except requests.exceptions.RequestException:
            continue

    logger.warning(f"Tüm RDAP kaynakları başarısız oldu: {query}")
    return None

def get_additional_info_from_ripestat(query):
    additional_data = {}
    endpoints = {
        "announced-prefixes": "Anons Edilen Prefixler", 
        "routing-status": "Yönlendirme Durumu",
        "bgp-state": "BGP Durumu"
    }
    
    for endpoint, title in endpoints.items():
        try:
            r = requests.get(f"{RIPESTAT_DATA_URL}{endpoint}/data.json", 
                             params={"resource": query}, 
                             timeout=7)
            if r.status_code == 200:
                additional_data[title] = r.json().get("data", {})
            else:
                additional_data[title] = {"error": f"HTTP {r.status_code}: Veri alınamadı"}
        except requests.exceptions.RequestException as e:
            additional_data[title] = {"error": f"İstek hatası: {str(e)}"}
        except Exception as e:
            additional_data[title] = {"error": f"Beklenmedik hata: {str(e)}"}
    
    return additional_data

def get_ipinfo_details(ip):
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip) and ":" not in ip:
        return None
    
    try:
        r = requests.get(f"{IPINFO_URL}{ip}/json", timeout=5)
        if r.status_code == 200:
            data = r.json()
            country_code = data.get('country', '')
            data['country_name'] = get_country_name(country_code)
            return data
        return None
    except requests.exceptions.RequestException as e:
        logger.warning(f"IPinfo bilgileri alınamadı: {str(e)}")
        return None

def analyze_ssl(hostname, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                cert_bin = ssl_sock.getpeercert(binary_form=True)
                cipher = ssl_sock.cipher()
                
                x509 = crypto.load_certificate(
                    crypto.FILETYPE_ASN1, 
                    cert_bin
                )
                
                issuer = x509.get_issuer()
                subject = x509.get_subject()

                not_after_naive = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                not_before_naive = datetime.strptime(x509.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')

                not_after = not_after_naive.replace(tzinfo=timezone.utc)
                not_before = not_before_naive.replace(tzinfo=timezone.utc)
                
                days_valid = (not_after - datetime.now(timezone.utc)).days
                
                return {
                    "issuer": {k.decode(): v.decode() for k, v in issuer.get_components()},
                    "subject": {k.decode(): v.decode() for k, v in subject.get_components()},
                    "valid_from": not_before.strftime("%Y-%m-%d"),
                    "valid_until": not_after.strftime("%Y-%m-%d"),
                    "days_remaining": days_valid,
                    "protocol": ssl_sock.version(),
                    "cipher": {
                        "name": cipher[0],
                        "version": cipher[1],
                        "bits": cipher[2]
                    } if cipher else None,
                    "serial_number": str(x509.get_serial_number()),
                    "signature_algorithm": x509.get_signature_algorithm().decode('utf-8'),
                    "is_valid": days_valid > 0,
                    "common_name": dict(subject.get_components()).get(b'CN', b'').decode('utf-8'),
                    "organization": dict(subject.get_components()).get(b'O', b'').decode('utf-8'),
                    "alt_names": _get_alt_names(x509)
                }
                
    except ssl.SSLError as e:
        logger.error(f"SSL hatası ({hostname}:{port}): {str(e)}")
        return {"error": f"SSL hatası: {str(e)}"}
    except socket.timeout:
        logger.error(f"Zaman aşımı ({hostname}:{port})")
        return {"error": "Bağlantı zaman aşımı"}
    except Exception as e:
        logger.error(f"Beklenmedik hata ({hostname}:{port}): {str(e)}")
        return {"error": f"Beklenmedik hata: {str(e)}"}

def _get_alt_names(x509):
    alt_names = []
    for i in range(x509.get_extension_count()):
        ext = x509.get_extension(i)
        if ext.get_short_name() == b'subjectAltName':
            alt_names.extend([name.strip() for name in str(ext).split(',')])
    return alt_names

def generate_security_report(ipinfo_data, http_headers, port_scan, dnsbl_results, ip):
    report = {
        "proxy_vpn_tor": False,
        "anonymity_services": [], 
        "open_ports": [],
        "security_headers": [],
        "server_info": {},
        "security_issues": []
    }

    report["anonymity_services"] = check_anonymity_services(ip)
    
    if report["anonymity_services"]:
        report["proxy_vpn_tor"] = True
        detected_str = ", ".join(report["anonymity_services"])
        report["security_issues"].append(
            f"Anonim ağ kullanımı tespit edildi: {detected_str}"
        )

    if ipinfo_data:
        if ipinfo_data.get("proxy"):
            if "Proxy" not in report["anonymity_services"]:
                report["anonymity_services"].append("Proxy")
        if ipinfo_data.get("vpn"):
            if "VPN" not in report["anonymity_services"]:
                report["anonymity_services"].append("VPN")
        if ipinfo_data.get("tor"):
            if "Tor" not in report["anonymity_services"]:
                report["anonymity_services"].append("Tor")

    if dnsbl_results:
        for category, listings in dnsbl_results.items():
            for entry in listings:
                if entry.get('response'):
                    category_map = {
                        'spam': 'Spam',
                        'proxy_bot': 'Proxy/Bot',
                        'anonymity': 'Anonim Servis'
                    }
                    
                    service_name = category_map.get(category, category.capitalize())
                    if service_name not in report["anonymity_services"]:
                        report["anonymity_services"].append(service_name)

    if port_scan and "ports" in port_scan:
        report["open_ports"] = port_scan["ports"]
        
        critical_ports = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080}
        open_critical = [p for p in report["open_ports"] if p["port"] in critical_ports]
        
        if open_critical:
            report["security_issues"].append(f"{len(open_critical)} kritik port açık bulundu")

    if http_headers and not http_headers.get("error") and "headers" in http_headers:
        headers = {k.lower(): v for k, v in http_headers["headers"].items()}
        
        security_headers_check = {
            "Content-Security-Policy": "content-security-policy",
            "Strict-Transport-Security": "strict-transport-security",
            "X-Frame-Options": "x-frame-options",
            "X-Content-Type-Options": "x-content-type-options",
            "X-XSS-Protection": "x-xss-protection"
        }
        
        report["security_headers"] = [
            display_name for display_name, real_name in security_headers_check.items() 
            if real_name in headers
        ]
        
        missing_headers = [
            display_name for display_name, real_name in security_headers_check.items() 
            if real_name not in headers
        ]
        if missing_headers:
            report["security_issues"].append(f"{len(missing_headers)} güvenlik başlığı eksik")

    return report

def check_anonymity_services(ip):
    anonymity_services = []
    proxy_lists = [
        'proxy.dnsbl.sorbs.net',
        'socks.dnsbl.sorbs.net',
        'http.dnsbl.sorbs.net',
        'tor.dan.me.uk',
        'torexit.dan.me.uk',
        'dnsbl.tornevall.org',
        'rbl.efnetrbl.org',
        'noptr.spamrats.com',
        'dyna.spamrats.com',
        'bl.blocklist.de',
        'dnsbl.dronebl.org'
    ]
    
    try:
        if '.' in ip:
            reversed_ip = '.'.join(reversed(ip.split('.')))
        else:
            reversed_ip = '.'.join(reversed(ip.split(':'))).replace(':', '')
            
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        resolver.timeout = 3
        resolver.lifetime = 3
        
        for dnsbl in proxy_lists:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                answers = resolver.resolve(query, 'A')
                if answers:
                    service_map = {
                        'sorbs': 'Proxy',
                        'dan': 'Tor',
                        'tornevall': 'VPN',
                        'efnetrbl': 'IRC Proxy',
                        'spamrats': 'Spam Bot',
                        'blocklist': 'Hack Saldırısı',
                        'dronebl': 'Zombie/Botnet'
                    }
                    
                    service_name = next(
                        (service_map[key] for key in service_map if key in dnsbl),
                        dnsbl.split('.')[-2].capitalize()
                    )
                    
                    if service_name not in anonymity_services:
                        anonymity_services.append(service_name)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logger.warning(f"DNSBL query error for {dnsbl}: {str(e)}")
                
        return anonymity_services
        
    except Exception as e:
        logger.error(f"Anonimlik kontrol hatası: {str(e)}")
        return []

def get_ip_classification(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "Private", "Özel ağ kullanımı (LAN)"
        elif ip_obj.is_multicast:
            return "Multicast", "Çoklu yayın ağı"
        elif ip_obj.is_global:
            return "Public", "Genel internet"
        else:
            return "Special", "Özel kullanım"
    except ValueError:
        return "Invalid", "Geçersiz IP adresi"

def robust_get_request(url, retries=3, backoff_factor=0.5, **kwargs):
    headers = kwargs.get('headers', {})
    headers.setdefault('User-Agent', 'GlobalIPASNTool/1.0 (Mozilla/5.0)')
    kwargs['headers'] = headers

    for i in range(retries):
        try:
            response = requests.get(url, **kwargs)
            response.raise_for_status()
            return response
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            if i == retries - 1:
                raise e
            wait_time = backoff_factor * (2 ** i)
            time.sleep(wait_time)
    return None
    
# Rotalar
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # Başlangıç değişkenlerini tanımla
    query = request.form.get("query", "").strip() if request.method == "POST" else ""
    main_data, additional_data, ipinfo_data, raw_json_str, error = None, None, None, None, None
    traceroute_locations, asn_map_data, origin_asn = None, None, None
    reverse_dns, ping_data, port_scan, http_headers, ssl_info = None, None, None, None, None
    dnsbl_results, security_report, bgp_graph_data = None, None, None
    bgpview_prefix, mtr_data, peeringdb_data = None, None, None

    # Yeni DNS değişkenleri
    dns_records, authoritative_dns, dnssec_status = None, None, None

    if request.method == "POST" and query:
        try:
            # Alan adı veya IP'yi çözümle
            ip_to_query = query
            is_domain = False
            try:
                addr_info = socket.getaddrinfo(query, None)
                ip_to_query = addr_info[0][4][0]
                is_domain = True
            except socket.gaierror:
                pass  # Bu bir IP adresi olabilir
            except Exception as e:
                logger.error(f"DNS çözümleme hatası: {str(e)}")

            # RDAP sorgusu ile başla
            authoritative_url = get_authoritative_rdap_url(ip_to_query)
            if authoritative_url:
                try:
                    r = robust_get_request(authoritative_url, timeout=15, headers={"Accept": "application/rdap+json"})
                    raw_data = r.json()
                    main_data = parse_rdap_response(raw_data)
                    ip_class, ip_class_desc = get_ip_classification(ip_to_query)
                    if main_data:
                        main_data["summary"]["ip_class"] = ip_class
                        main_data["summary"]["ip_class_desc"] = ip_class_desc
                    raw_json_str = json.dumps(raw_data, indent=2, ensure_ascii=False)
                except requests.exceptions.HTTPError as http_err:
                    error = f"API Hatası (Kod: {http_err.response.status_code}): '{query}' için kayıt bulunamadı."
                except Exception as e:
                    error = f"RDAP verisi alınamadı: {str(e)}"
            else:
                error = f"Yetkili RDAP sunucusu bulunamadı: {query}"
            
            if error:
                logger.error(error)

            # RDAP'de hata yoksa, diğer analizleri paralel olarak yap
            if not error:
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    # Paralel çalışacak görevleri tanımla
                    tasks = {
                        'ipinfo': executor.submit(get_ipinfo_details, ip_to_query),
                        'ripestat': executor.submit(get_additional_info_from_ripestat, ip_to_query),
                        'reverse_dns': executor.submit(get_reverse_dns, ip_to_query),
                        'ping': executor.submit(get_ping_latency, ip_to_query),
                        'dnsbl': executor.submit(check_dnsbl, ip_to_query),
                        'mtr': executor.submit(run_mtr_analysis, ip_to_query),
                        'bgpview': executor.submit(get_bgpview_prefix_details, ip_to_query),
                        'traceroute': executor.submit(enriched_traceroute, ip_to_query)
                    }
                    # Sonuçları topla
                    results = {name: future.result() for name, future in tasks.items()}

                ipinfo_data = results.get('ipinfo')
                additional_data = results.get('ripestat')
                reverse_dns = results.get('reverse_dns')
                ping_data = results.get('ping')
                mtr_data = results.get('mtr')
                dnsbl_results = results.get('dnsbl')
                bgpview_prefix = results.get('bgpview')
                traceroute_locations = results.get('traceroute')

                # Alan adıysa DNS kayıtlarını al
                if is_domain:
                    try:
                        dns_records = get_dns_records(query)
                        authoritative_dns = get_authoritative_dns(query)
                        dnssec_status = check_dnssec(query)
                    except Exception as e:
                        logger.error(f"DNS sorgu hatası: {str(e)}")
                        # Hata durumunda boş döndür
                        dns_records, authoritative_dns, dnssec_status = {}, None, "Hata"

                # ASN'yi ipinfo'dan al, yoksa RIPEstat'tan dene
                if ipinfo_data and ipinfo_data.get('asn'):
                    origin_asn = ipinfo_data['asn'].get('asn', '').replace("AS", "")
                else:
                    origin_asn = get_asn_from_ip(ip_to_query)
                
                # ASN bilgisiyle PeeringDB'yi sorgula (bu sıralı olmalı)
                peeringdb_data = get_peeringdb_info(origin_asn)

                # Sıralı çalışması gereken diğer görevler
                target_host = query if is_domain else ip_to_query
                http_headers = get_http_headers(target_host)
                if http_headers and not http_headers.get("error"):
                    ssl_info = analyze_ssl(target_host)

                if NMAP_AVAILABLE:
                    port_scan = scan_ports(ip_to_query)
                else:
                    port_scan = {"error": "Nmap kurulu değil"}

                _, asn_map_data = get_asn_map_data(ip_to_query)

                security_report = generate_security_report(
                    ipinfo_data, http_headers, port_scan, dnsbl_results, ip_to_query
                )

                if additional_data and 'BGP Durumu' in additional_data:
                    bgp_graph_data = process_bgp_data_for_d3(additional_data['BGP Durumu'], origin_asn)

                # Arama aktivitesini kaydet
                new_log = ActivityLog(user_id=current_user.id, search_term=query, source='web')
                db.session.add(new_log)
                db.session.commit()

        except requests.exceptions.ConnectionError as conn_err:
            error = f"Bağlantı hatası: {str(conn_err)}"
            logger.error(error)
        except Exception as e:
            error = f"Beklenmedik bir hata oluştu: {str(e)}"
            logger.error(f"Ana işlem hatası: {str(e)}", exc_info=True)
            
    elif request.method == "POST" and not query:
        error = "Lütfen bir IP adresi veya alan adı girin."
    
    # Tüm toplanan verileri şablona gönder
    return render_template(
        "index.html",
        query=query,
        data=main_data,
        additional_data=additional_data,
        ipinfo_data=ipinfo_data,
        raw_json=raw_json_str,
        error=error,
        nmap_available=NMAP_AVAILABLE,
        traceroute_locations=traceroute_locations,
        origin_asn=origin_asn,
        asn_map_data=asn_map_data,
        reverse_dns=reverse_dns,
        ping_data=ping_data,
        port_scan=port_scan,
        http_headers=http_headers,
        security_report=security_report,
        ssl_info=ssl_info,
        dnsbl_results=dnsbl_results,
        bgp_graph_data=bgp_graph_data,
        mtr_data=mtr_data, 
        bgpview_prefix=bgpview_prefix,
        peeringdb_data=peeringdb_data,
        # YENİ EKLENEN KISIM
        dns_records=dns_records,
        authoritative_dns=authoritative_dns,
        dnssec_status=dnssec_status
    )

@app.route("/api/analyze", methods=["POST"])
@api_key_required
def api_analyze(user):
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({"error": "Missing 'ip' in request body"}), 400
        
        query = data['ip'].strip()
        if not query:
            return jsonify({"error": "IP address cannot be empty"}), 400
        
        new_log = ActivityLog(
            user_id=user.id,
            search_term=query,
            source='api'
        )
        db.session.add(new_log)
        db.session.commit()
        
        result = perform_analysis(query)
        
        response = {
            "status": "success",
            "query": query,
            "data": result.get("main_data"),
            "additional_data": result.get("additional_data"),
            "ipinfo_data": result.get("ipinfo_data"),
            "reverse_dns": result.get("reverse_dns"),
            "ping_data": result.get("ping_data"),
            "port_scan": result.get("port_scan"),
            "http_headers": result.get("http_headers"),
            "traceroute_locations": result.get("traceroute_locations"),
            "asn_map_data": result.get("asn_map_data"),
            "origin_asn": result.get("origin_asn"),
            "security_report": result.get("security_report"),
            "ssl_info": result.get("ssl_info"),
            "raw_rdap": result.get("raw_json_str") 
        }
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"API error: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            return render_template('register.html', error='Kullanıcı adı veya email zaten kullanımda')
        
        api_key = secrets.token_hex(16)
        
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(
                username=username, 
                email=email, 
                password=hashed_password,
                api_key=api_key
            )
            db.session.add(new_user)
            db.session.commit()
            
            login_user(new_user)
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Kayıt hatası: {str(e)}")
            return render_template('register.html', error='Kayıt sırasında bir hata oluştu')
    
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Geçersiz kullanıcı adı veya şifre')
    
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/profile")
@login_required
def profile():
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    activities = ActivityLog.query.filter(
        ActivityLog.user_id == current_user.id,
        ActivityLog.timestamp >= seven_days_ago
    ).order_by(ActivityLog.timestamp.desc()).all()
    
    return render_template(
        'profile.html',
        user=current_user,
        activities=activities
    )

def perform_analysis(query):
    result = {
        "main_data": None,
        "additional_data": None,
        "ipinfo_data": None,
        "raw_json_str": None,
        "error": None,
        "traceroute_locations": None,
        "origin_asn": None,
        "asn_map_data": None,
        "reverse_dns": None,
        "ping_data": None,
        "port_scan": None,
        "http_headers": None,
        "ssl_info": None,
        "security_report": None,
        "mtr_data": None, # Eklendi
        "bgpview_prefix": None, # Eklendi
        "peeringdb_data": None # Eklendi
    }

    try:
        ip_to_query = query
        is_domain = False
        
        try:
            addr_info = socket.getaddrinfo(query, None)
            ip_to_query = addr_info[0][4][0]
            is_domain = True
        except socket.gaierror:
            pass
        except Exception as e:
            logger.error(f"DNS resolution error: {str(e)}")
        
        ip_class, ip_class_desc = get_ip_classification(ip_to_query)
        
        authoritative_url = get_authoritative_rdap_url(ip_to_query)
        if authoritative_url:
            try:
                r = requests.get(authoritative_url, timeout=15, headers={"Accept": "application/rdap+json"})
                r.raise_for_status()
                raw_data = r.json()
                main_data = parse_rdap_response(raw_data)
                if main_data:
                    main_data["summary"]["ip_class"] = ip_class
                    main_data["summary"]["ip_class_desc"] = ip_class_desc
                result["main_data"] = main_data
                result["raw_json_str"] = json.dumps(raw_data, indent=2, ensure_ascii=False)
            except requests.exceptions.HTTPError as http_err:
                result["error"] = f"API Error (Code: {http_err.response.status_code}): No record found for '{query}'"
            except Exception as e:
                result["error"] = f"Failed to get RDAP data: {str(e)}"
        else:
            result["error"] = "Authoritative RDAP URL not found"
        
        if not result["error"]:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                tasks = {
                    'ipinfo': executor.submit(get_ipinfo_details, ip_to_query),
                    'ripestat': executor.submit(get_additional_info_from_ripestat, ip_to_query),
                    'reverse_dns': executor.submit(get_reverse_dns, ip_to_query),
                    'ping': executor.submit(get_ping_latency, ip_to_query),
                    'dnsbl': executor.submit(check_dnsbl, ip_to_query),
                    'mtr': executor.submit(run_mtr_analysis, ip_to_query),
                    'bgpview': executor.submit(get_bgpview_prefix_details, ip_to_query),
                    'traceroute': executor.submit(enriched_traceroute, ip_to_query) # Burası güncellendi
                }
                for name, future in tasks.items():
                    try:
                        result[name] = future.result()
                    except Exception as e:
                        logger.error(f"Error during parallel task {name}: {str(e)}")
                        result[name] = {"error": f"Error: {str(e)}"}

            # ASN'yi ipinfo'dan al, yoksa RIPEstat'tan dene
            if result["ipinfo_data"] and result["ipinfo_data"].get('asn'):
                result["origin_asn"] = result["ipinfo_data"]['asn'].get('asn', '').replace("AS", "")
            else:
                result["origin_asn"] = get_asn_from_ip(ip_to_query)
            
            # ASN bilgisiyle PeeringDB'yi sorgula (bu sıralı olmalı)
            result["peeringdb_data"] = get_peeringdb_info(result["origin_asn"])

            # Sıralı çalışması gereken diğer görevler
            target_host = query if is_domain else ip_to_query
            result["http_headers"] = get_http_headers(target_host)
            if result["http_headers"] and not result["http_headers"].get("error"):
                result["ssl_info"] = analyze_ssl(target_host)
            
            if NMAP_AVAILABLE:
                result["port_scan"] = scan_ports(ip_to_query)
            else:
                result["port_scan"] = {"error": "Nmap not installed"}
            
            # asn_map_data
            if result["origin_asn"]: # origin_asn mevcutsa harita verilerini al
                _, result["asn_map_data"] = get_asn_map_data(ip_to_query)

            result["security_report"] = generate_security_report(
                result["ipinfo_data"],
                result["http_headers"],
                result["port_scan"],
                result["dnsbl"], # dnsbl_results olarak geldi
                ip_to_query
            )
    
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        logger.error(f"Analysis error: {str(e)}", exc_info=True)
    
    return result

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        logger.info("Veritabanı başlatıldı")

    if SCAPY_AVAILABLE and os.name == "posix" and os.geteuid() != 0:
        logger.warning("Scapy kullanımı için root yetkisi gerekli")
    
    if not NMAP_AVAILABLE:
        logger.warning("NMAP desteği devre dışı")

    app.run(debug=True, host='0.0.0.0', port=5000)
