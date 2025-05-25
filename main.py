import streamlit as st
from analysis import analyze_url
import pandas as pd

st.set_page_config(page_title="Detector de Phishing", layout="wide")
st.title("Detector de Phishing")

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