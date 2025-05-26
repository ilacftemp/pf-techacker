import streamlit as st
from analysis import analyze_url
import pandas as pd
import altair as alt

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
    with st.spinner("Analisando..."):
        resultado = analyze_url(url)
        st.success("Análise concluída!")

        for chave, valor in resultado.items():
            if isinstance(valor, dict):
                st.subheader(chave)
                if chave in explicacoes:
                    st.markdown(f"""
                    <div style='
                        background-color: #222;
                        padding: 10px;
                        border-left: 4px solid #999;
                        font-size: 1.05rem;
                        color: #e0e0e0;
                        margin-bottom: 10px;
                    '>
                    {explicacoes[chave]}
                    </div>
                    """, unsafe_allow_html=True)
                st.table(pd.DataFrame(valor.items(), columns=["Indicador", "Valor"]))
            else:
                if chave == "Score de Risco":
                    if valor == "Alto":
                        st.error(f"Risco de Phishing: {valor}")
                    elif valor == "Médio":
                        st.warning(f"Risco de Phishing: {valor}")
                    else:
                        st.success(f"Risco de Phishing: {valor}")
                else:
                    st.markdown(f"**{chave}:** {valor}")

        st.session_state.historico.append(resultado)

if st.session_state.historico:
    st.markdown("---")
    st.subheader("Histórico das Análises nesta Sessão")
    historico_df = pd.DataFrame([
        {
            "URL": r["URL"],
            "Risco": r["Score de Risco"],
        } for r in st.session_state.historico
    ])
    st.dataframe(historico_df)

    if st.button("Exportar histórico para CSV"):
        historico_df.to_csv("historico.csv", index=False)
        st.success("Arquivo salvo como historico.csv")

    st.markdown("### Distribuição de Risco na Sessão")
    riscos = pd.Series([r["Score de Risco"] for r in st.session_state.historico])
    df_risco = riscos.value_counts().reset_index()
    df_risco.columns = ["Risco", "Contagem"]

    cor_map = {
        "Alto": "#d62728",
        "Médio": "#ff7f0e",
        "Baixo": "#2ca02c"
    }

    grafico = alt.Chart(df_risco).mark_bar(size=60).encode(
        x=alt.X("Risco:N", sort=["Alto", "Médio", "Baixo"], title="Nível de Risco"),
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
