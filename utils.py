import re
import ssl
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from Levenshtein import distance
from dotenv import load_dotenv
import os
import json
from datetime import datetime


load_dotenv()
GSB_API_KEY = os.getenv("GSB_API_KEY")


def get_hostname(url):
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).hostname


def check_google_safebrowsing(url, api_key):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    headers = {"Content-Type": "application/json"}

    body = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, headers=headers, data=json.dumps(body))
        result = response.json()
        return bool(result.get("matches"))
    except Exception as e:
        return False


def check_all_phishing_domains(url):
    try:
        with open('ALL-phishing-domains.txt', 'r') as file:
            phishing_domains = file.read().splitlines()
        hostname = get_hostname(url)
        return hostname in phishing_domains
    except FileNotFoundError:
        print("Arquivo ALL-phishing-domains.txt não encontrado.")
        return False


def check_lists(url):
    google_safe = check_google_safebrowsing(url, GSB_API_KEY)
    all_phishing = check_all_phishing_domains(url)

    return {
        "Google Safe Browsing": google_safe,
        "ALL-phishing-domains": all_phishing
    }


def check_heuristics(url):
    return {
        "Números no domínio": bool(re.search(r'[0-9]', url)),
        "Subdomínios excessivos": url.count('.') > 3,
        "Caracteres suspeitos": bool(re.search(r'[@%$!]', url))
    }


def check_whois(url):
    try:
        domain = get_hostname(url)
        tld = domain.split('.')[-1]

        if tld in ['com', 'net']:
            server = "whois.verisign-grs.com"
        else:
            return {"Data de criação": "Indisponível"}

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((server, 43))
            s.send((domain + "\r\n").encode())

            response = b""
            while True:
                data = s.recv(1024)
                if not data:
                    break
                response += data

        decoded = response.decode(errors="ignore")

        match = re.search(r'Creation Date:\s*(.+)', decoded)
        if match:
            creation_date = match.group(1).strip()
            return {"Data de criação": creation_date}
        else:
            return {"Data de criação": "Não encontrada"}

    except Exception as e:
        return {"Data de criação": "Erro"}


def check_ssl(url):
    try:
        host = get_hostname(url)
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                emissores = []
                for tupla in cert.get('issuer', []):
                    for k, v in tupla:
                        emissores.append(f"{k}={v}")
                emissor_str = " / ".join(emissores) or "Desconhecido"
                validade = cert.get('notAfter', "Desconhecido")

                try:
                    validade_data = datetime.strptime(validade, "%b %d %H:%M:%S %Y %Z")
                    expirado = validade_data < datetime.utcnow()
                except:
                    expirado = True

                if any(x in emissor_str for x in ["Let's Encrypt", "Google Trust", "DigiCert", "GlobalSign", "Sectigo"]):
                    risco_ssl = "baixo"
                elif any(x in emissor_str for x in ["cPanel", "ZeroSSL", "Buypass", "TrustAsia"]):
                    risco_ssl = "médio"
                elif "Erro" in emissor_str or emissor_str == "Desconhecido":
                    risco_ssl = "alto"
                else:
                    risco_ssl = "médio"

                return {
                    "Emissor": emissor_str,
                    "Válido até": validade,
                    "Expirado": expirado,
                    "Risco do Emissor": risco_ssl
                }
    except:
        return {
            "Emissor": "Erro",
            "Válido até": "Erro",
            "Expirado": True,
            "Risco do Emissor": "alto"
        }


def check_levenshtein(url):
    dominios_reais = [
        "google.com", "paypal.com", "apple.com", "microsoft.com",
        "facebook.com", "amazon.com", "netflix.com", "twitter.com",
        "youtube.com", "instagram.com", "linkedin.com", "adobe.com",
        "icloud.com", "dropbox.com", "whatsapp.com", "tiktok.com",
        "bing.com", "spotify.com", "salesforce.com", "zoom.us"
    ]
    dominio = get_hostname(url)
    return {marca: distance(dominio, marca) for marca in dominios_reais}


def analyze_html(url):
    try:
        if not url.startswith("http"):
            url = "http://" + url
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        sensitive = any("password" in str(f).lower() or "login" in str(f).lower() for f in forms)
        return {"Formulários": len(forms), "Pede dados sensíveis": sensitive}
    except:
        return {"Formulários": 0, "Pede dados sensíveis": False}
    
    
def check_dns_dinamico(hostname):
    dinamicos = ['no-ip', 'dyndns', 'duckdns', 'hopto.org', 'freeddns.org', 'myftp.biz']
    return any(d in hostname for d in dinamicos)


def detecta_redirecionamento(url):
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        return len(r.history) > 1
    except:
        return False