import streamlit as st
from analysis import analyze_url
import pandas as pd

st.set_page_config(page_title="Detector de Phishing", layout="wide")
st.title("Detector de Phishing")

explicacoes = {
    "Verificação em listas de phishing": "Verifica se a URL consta em bases como Google Safe Browsing. Peso: +2 se presente.",
    "Heurísticas básicas": "Detecta padrões suspeitos na URL como subdomínios excessivos ou símbolos. Peso: +1 se ≥2.",
    "WHOIS": "Domínios recém-criados (< 30 dias) são mais suspeitos. Peso: +1.",
    "Certificado SSL": "Avalia se há certificado, se está vencido e a reputação do emissor. Peso: +1 a +2.",
    "Similaridade com marcas conhecidas": "Detecta imitações de domínios reais. Peso: até +2.",
    "Conteúdo HTML": "Presença de formulários e campos como senha/login. Peso: até +2.5.",
    "Redirecionamento suspeito": "Múltiplos redirecionamentos são comuns em phishing. Peso: +1."
}

# Armazena histórico em tempo de execução
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
                    st.caption(explicacoes[chave])
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
    st.bar_chart(riscos.value_counts())