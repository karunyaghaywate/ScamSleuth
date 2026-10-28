
import streamlit as st
from scamsleuth import analyze_url

st.set_page_config(
    page_title="ScamSleuth",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ ScamSleuth")
st.subheader("Your Digital Scam Detective")
st.write("Investigate suspicious URLs before you click.")

url = st.text_input(
    "Enter a URL to analyze",
    placeholder="https://example.com"
)

if st.button("🔍 Analyze URL", use_container_width=True):
    if not url.strip():
        st.warning("Please enter a URL first.")
    else:
        host, findings, score = analyze_url(url)

        if host is None:
            st.error(findings[0])
        else:
            st.divider()
            st.subheader("Analysis Results")
            st.metric("Risk Indicator", f"{score}/100")
            st.progress(score)

            if score >= 35:
                st.error("Higher Risk Indicators")
            elif score >= 15:
                st.warning("Some Warning Signs")
            else:
                st.success("Few Warning Signs Detected")

            st.write("**Domain:**", host)
            st.write("**Findings:**")

            for finding in findings:
                st.write(f"- {finding}")

            st.caption(
                "This tool uses basic rules and cannot "
                "guarantee a website is safe."
            )
