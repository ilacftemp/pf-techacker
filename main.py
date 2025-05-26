import streamlit as st
from analysis import analyze_url
import pandas as pd
import altair as alt
import re
from datetime import datetime
from utils import get_hostname
import requests

def is_url_valida(u):
    if not u:
        return False
    if not u.startswith("http"):
        u = "http://" + u
    dominio = get_hostname(u)
    return dominio and "." in dominio

st.set_page_config(page_title="Detector de Phishing", layout="wide")
st.title("Detector de Phishing")

explicacoes = {
    "Verificação em listas de phishing": (
        "Confere se a URL aparece no Google Safe Browsing, que contém um banco de dados com URLs suspeitas ou conhecidamente perigosas, além de checar se aparece na lista ALL-phishing-domains do repositório Phishing.Database. "
        "URLs já denunciadas têm alta probabilidade de phishing."
    ),
    "Heurísticas básicas": (
        "Analisa a estrutura da URL em busca de padrões suspeitos, como subdomínios excessivos, números ou símbolos. "
        "Esses padrões são comuns em domínios criados para enganar visualmente."
    ),
    "WHOIS": (
        "Verifica a data de criação do domínio. Endereços recém-registrados são frequentemente usados em ataques rápidos, "
        "antes de serem detectados."
    ),
    "Certificado SSL": (
        "Avalia se o site possui um certificado válido, se ele está expirado e quem o emitiu. "
        "Certificados de emissores pouco confiáveis ou vencidos aumentam o risco."
    ),
    "Similaridade com marcas conhecidas": (
        "Compara o domínio analisado com domínios legítimos de grandes empresas. "
        "Diferenças sutis indicam tentativa de imitação (ex: troca de letras)."
    ),
    "Conteúdo HTML": (
        "Detecta formulários no site, especialmente os que solicitam login, senha ou dados sensíveis. "
        "Esse tipo de conteúdo é típico em páginas de captura de credenciais."
    ),
    "Redirecionamento suspeito": (
        "Identifica se a URL redireciona várias vezes antes de exibir o conteúdo final. "
        "Essa técnica é comum para ocultar o destino real da página."
    )
}

if "historico" not in st.session_state:
    st.session_state.historico = []

url = st.text_input("Digite a URL para análise:")

if st.button("Analisar"):
    if not is_url_valida(url):
        st.error("Por favor, digite uma URL válida (ex: https://exemplo.com ou exemplo.com)")
    else:
        with st.spinner("Analisando..."):
            resultado = analyze_url(url)
        st.success("Análise concluída!")

        st.subheader(f"URL: {resultado['URL']}")

        if "Motivo" in resultado:
            st.info(resultado["Motivo"])

        for chave, valor in resultado.items():
            if chave in ("Riscos Parciais", "URL", "Domínio", "Motivo"):
                continue

            risco_parcial = resultado.get("Riscos Parciais", {}).get(chave)
            if risco_parcial is not None:
                st.subheader(f"{chave} — Pontuação: {risco_parcial} ponto(s)")
            else:
                st.subheader(chave)

            if chave in explicacoes:
                st.markdown(f"""
                <div style='background-color: #222; padding: 10px; border-left: 4px solid #999;
                            font-size: 1.05rem; color: #e0e0e0; margin-bottom: 10px;'>
                    {explicacoes[chave]}
                </div>
                """, unsafe_allow_html=True)

            if chave == "Score de Risco":
                nivel = re.match(r"(Alto|Médio|Baixo)", valor).group(1)
                if nivel == "Alto":
                    st.error(f"Risco de Phishing: {valor}")
                elif nivel == "Médio":
                    st.warning(f"Risco de Phishing: {valor}")
                else:
                    st.success(f"Risco de Phishing: {valor}")

            elif chave == "WHOIS":
                data_criacao = valor.get("Data de criação")
                idade_str = "Desconhecida"
                try:
                    data = datetime.strptime(data_criacao[:10], "%Y-%m-%d")
                    hoje = datetime.utcnow()
                    delta = hoje - data
                    anos = hoje.year - data.year
                    meses = hoje.month - data.month
                    dias = hoje.day - data.day
                    if dias < 0:
                        meses -= 1
                        dias += (data.replace(month=data.month + 1, day=1) - data.replace(day=1)).days
                    if meses < 0:
                        anos -= 1
                        meses += 12
                    idade_str = f"{anos} ano(s), {meses} mês(es), {dias} dia(s)"
                except:
                    pass
                df = pd.DataFrame([["Data de criação", data_criacao, idade_str]], columns=["Indicador", "Valor", "Idade"])
                st.table(df)

            elif isinstance(valor, dict):
                st.table(pd.DataFrame(valor.items(), columns=["Indicador", "Valor"]))

            elif isinstance(valor, (str, bool, int, float)):
                df = pd.DataFrame([[chave, valor]], columns=["Indicador", "Valor"])
                st.table(df)

            else:
                st.markdown(f"**Valor:** {valor}")

        st.session_state.historico.append(resultado)

# 🔽 HISTÓRICO E GRÁFICO - FORA DO BOTÃO
if st.session_state.historico:
    st.markdown("---")
    st.subheader("Histórico das Análises nesta Sessão")

    historico_df = pd.DataFrame([
        {
            "URL": r["URL"],
            "Risco": r["Score de Risco"]
        } for r in st.session_state.historico
    ])
    st.dataframe(historico_df)

    if st.button("Exportar histórico para CSV"):
        historico_df.to_csv("historico.csv", index=False)
        st.success("Arquivo salvo como historico.csv")

    st.markdown("### Distribuição de Risco na Sessão")

    def extrair_nivel(score_str):
        match = re.match(r"(Alto|Médio|Baixo)", score_str)
        return match.group(1) if match else "Desconhecido"

    riscos = pd.Series([extrair_nivel(r["Score de Risco"]) for r in st.session_state.historico])
    df_risco = riscos.value_counts().reset_index()
    df_risco.columns = ["Risco", "Contagem"]

    cor_map = {
        "Alto": "#d62728",
        "Médio": "#ff7f0e",
        "Baixo": "#2ca02c"
    }

    grafico = alt.Chart(df_risco).mark_bar(size=60).encode(
        x=alt.X("Risco:N", sort=["Baixo", "Médio", "Alto"], title="Nível de Risco"),
        y=alt.Y("Contagem:Q", title="Quantidade"),
        color=alt.Color("Risco:N", scale=alt.Scale(domain=list(cor_map.keys()), range=list(cor_map.values())), legend=None),
        tooltip=["Risco", "Contagem"]
    ).properties(
        width=500,
        height=300,
        title="Frequência dos Níveis de Risco"
    ).configure_axis(
        labelFontSize=13,
        titleFontSize=14
    ).configure_title(
        fontSize=16
    ).configure_view(
        stroke=None
    )

    st.altair_chart(grafico)