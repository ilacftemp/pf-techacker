from utils import (check_lists, check_heuristics, check_whois, check_ssl, check_levenshtein, analyze_html, get_hostname, check_dns_dinamico, detecta_redirecionamento)
from datetime import datetime

# Lista de domínios reconhecidos como confiáveis
WHITELIST_DOMINIOS_CONFIAVEIS = {
    "google.com", "facebook.com", "youtube.com", "amazon.com", "microsoft.com",
    "apple.com", "paypal.com", "netflix.com", "twitter.com", "instagram.com",
    "linkedin.com", "adobe.com", "icloud.com", "dropbox.com", "whatsapp.com",
    "tiktok.com", "bing.com", "spotify.com", "salesforce.com", "zoom.us"
}

def analyze_url(url):
    hostname = get_hostname(url)

    if hostname in WHITELIST_DOMINIOS_CONFIAVEIS:
        return {
            "URL": url,
            "Domínio": hostname,
            "Motivo": "Este domínio consta em uma lista branca de domínios globalmente reconhecidos como seguros.",
            "Score de Risco": "Baixo (0) — domínio reconhecido como confiável, demais testes ignorados."
        }

    resultado = {
        "URL": url,
        "Verificação em listas de phishing": check_lists(url),
        "Heurísticas básicas": check_heuristics(url),
        "WHOIS": check_whois(url),
        "Certificado SSL": check_ssl(url),
        "Similaridade com marcas conhecidas": check_levenshtein(url),
        "Conteúdo HTML": analyze_html(url),
        "Redirecionamento suspeito": detecta_redirecionamento(url),
    }

    score = calcular_score(resultado)
    resultado["Score de Risco"] = score
    return resultado

def is_domain_new(data_str):
    try:
        data_str = data_str.strip()
        data = datetime.strptime(data_str[:10], "%Y-%m-%d")
        return (datetime.utcnow() - data).days < 30
    except:
        return False

def calcular_score(resultado):
    risco_total = 0
    riscos_parciais = {}

    def add(cat, valor):
        nonlocal risco_total
        riscos_parciais[cat] = valor
        risco_total += valor

    # Listas de phishing
    add("Verificação em listas de phishing", 2 if any(resultado["Verificação em listas de phishing"].values()) else 0)

    # Heurísticas
    heuristicas = resultado["Heurísticas básicas"]
    risco_h = 0
    if heuristicas.get("Números no domínio", False): risco_h += 0.5
    if heuristicas.get("Subdomínios excessivos", False): risco_h += 1.5
    if heuristicas.get("Caracteres suspeitos", False): risco_h += 1
    add("Heurísticas básicas", risco_h)

    # WHOIS
    data_criacao = resultado["WHOIS"].get("Data de criação", "")
    if data_criacao in ("", "Indisponível", "Erro", "Não encontrada"):
        add("WHOIS", 0.5)
    else:
        add("WHOIS", 1 if is_domain_new(data_criacao) else 0)

    # SSL
    ssl = resultado["Certificado SSL"]
    risco_ssl = 0
    if ssl.get("Emissor") == "Sem certificado": risco_ssl += 2
    if ssl.get("Risco do Emissor") == "alto": risco_ssl += 1
    elif ssl.get("Risco do Emissor") == "médio": risco_ssl += 0.5
    if ssl.get("Expirado"): risco_ssl += 2
    add("Certificado SSL", risco_ssl)

    # HTML
    form_data = resultado["Conteúdo HTML"]
    risco_html = 0
    if form_data.get("Formulários", 0) > 0: risco_html += 0.5
    if form_data.get("Pede dados sensíveis"): risco_html += 2
    add("Conteúdo HTML", risco_html)

    # Levenshtein
    levenshteins = resultado["Similaridade com marcas conhecidas"].values()
    risco_lev = 0
    if any(d in (1, 2, 3) for d in levenshteins): risco_lev += 2
    elif sum(1 for d in levenshteins if 0 < d <= 3) >= 2: risco_lev += 1.5
    elif any(0 < d <= 3 for d in levenshteins): risco_lev += 1
    add("Similaridade com marcas conhecidas", risco_lev)

    # DNS dinâmico
    add("DNS dinâmico", 1 if check_dns_dinamico(get_hostname(resultado["URL"])) else 0)

    # Redirecionamento
    add("Redirecionamento suspeito", 1 if resultado.get("Redirecionamento suspeito") else 0)

    # Atribuir os riscos parciais no resultado
    resultado["Riscos Parciais"] = riscos_parciais

    if risco_total >= 4:
        return f"Alto ({risco_total})"
    elif risco_total >= 2:
        return f"Médio ({risco_total})"
    else:
        return f"Baixo ({risco_total})"