from utils import check_lists, check_heuristics, check_whois, check_ssl, check_levenshtein, analyze_html, get_hostname, check_dns_dinamico, detecta_redirecionamento, check_all_phishing_domains
from datetime import datetime

def analyze_url(url):
    resultado = {
        "URL": url,
        "Verificação em listas de phishing": check_lists(url),
        "Verificação na base de dados de phishing": check_all_phishing_domains(url),
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
    risco = 0

    if any(resultado["Verificação em listas de phishing"].values()):
        risco += 2

    if resultado["Verificação na base de dados de phishing"]:
        risco += 2

    heuristicas = resultado["Heurísticas básicas"]
    if heuristicas.get("Números no domínio", False):
        risco += 0.5
    if heuristicas.get("Subdomínios excessivos", False):
        risco += 1.5
    if heuristicas.get("Caracteres suspeitos", False):
        risco += 1

    data_criacao = resultado["WHOIS"].get("Data de criação", "")
    if is_domain_new(data_criacao):
        risco += 1

    if resultado["Certificado SSL"].get("Emissor") == "Sem certificado":
        risco += 2

    if resultado["Certificado SSL"].get("Risco do Emissor") == "alto":
        risco += 1
    elif resultado["Certificado SSL"].get("Risco do Emissor") == "médio":
        risco += 0.5

    if resultado["Certificado SSL"].get("Expirado"):
        risco += 2

    form_data = resultado["Conteúdo HTML"]

    if form_data.get("Formulários", 0) > 0:
        risco += 0.5

    if form_data.get("Pede dados sensíveis"):
        risco += 2

    levenshteins = resultado["Similaridade com marcas conhecidas"].values()
    if any(d == 1 for d in levenshteins):
        risco += 2
    elif sum(1 for d in levenshteins if 0 < d <= 3) >= 2:
        risco += 1.5
    elif any(0 < d <= 3 for d in levenshteins):
        risco += 1

    if check_dns_dinamico(get_hostname(resultado["URL"])):
        risco += 1

    if resultado.get("Redirecionamento suspeito"):
        risco += 1


    if risco >= 4:
        return "Alto"
    elif risco >= 2:
        return "Médio"
    else:
        return "Baixo"