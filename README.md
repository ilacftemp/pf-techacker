# PF-TECHACKER – Detector de Phishing

Aplicação interativa que analisa URLs suspeitas com base em múltiplas verificações: listas negras, heurísticas, WHOIS, SSL, análise de conteúdo e comparação com domínios legítimos. Ideal para demonstrar conceitos de segurança da informação e classificação de risco em páginas web.

## Funcionalidades

- Verificação com Google Safe Browsing (API real)
- Heurísticas de URL (subdomínios, caracteres, números)
- Consulta WHOIS (via socket, com extração da data de criação)
- Análise de certificado SSL
- Similaridade com domínios legítimos (distância de Levenshtein)
- Análise de conteúdo HTML (formulários e campos sensíveis)
- Interface via Streamlit
- Score de risco (baixo / médio / alto)
- Histórico de URLs analisadas com exportação CSV
- Uso de `.env` para proteger chave da API

## Estrutura do projeto

PF-TECHACKER/
├── main.py             # Interface Streamlit
├── analysis.py         # Logica de analise de risco
├── utils.py            # Modulos tecnicos (SSL, WHOIS, HTML, GSB)
├── requirements.txt    # Dependencias
├── .env                # (nao enviado ao Git) Sua chave da API
├── template.env        # Exemplo de .env para distribuicao
├── historico.csv       # Exportacoes da sessao
└── README.md


## Como executar

1. Clone o repositório:

```bash
git clone https://github.com/seuusuario/pf-techacker.git
cd pf-techacker
```

2. Crie um ambiente virtual:

```bash
python -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows
```

3. Instale as dependencias:

```bash
pip install -r requirements.txt
```

4. Configure sua chave do Google Safe Browsing:

- Copie o arquivo template.env para .env
- Coloque sua chave real no campo GSB_API_KEY

```bash
GSB_API_KEY=sua-chave-aqui
```

5. Execute a aplicacao:

```bash
streamlit run main.py
```

## Como obter a chave do Google Safe Browsing

1. Acesse https://console.cloud.google.com  
2. Crie um projeto novo  
3. Ative a **Safe Browsing API**  
4. Vá em APIs & Serviços > Credenciais > Criar chave de API  
5. Copie e cole no arquivo `.env`

## Observação acadêmica

Este projeto foi desenvolvido como parte da disciplina **Techacker (2025/1)** para demonstrar conceitos de verificação automática de URLs suspeitas.  
O foco foi em integração real de APIs, análise heurística e visualização interativa.