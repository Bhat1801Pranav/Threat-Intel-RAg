import streamlit as st
import requests

API_URL = "http://localhost:8000"

st.set_page_config(page_title="Threat Intel & AppSec RAG", page_icon="🛡️", layout="wide")
st.title("🛡️ Local Threat Intelligence & AppSec RAG Console")
st.caption("100% Air-Gapped Security Analysis | Powered by Ollama (Llama 3.2:1b), ChromaDB & FastAPI")

with st.sidebar:
    st.header("⚙️ System & KEV Feed")
    if st.button("Check API Health"):
        try:
            r = requests.get(f"{API_URL}/health", timeout=5).json()
            st.success(f"Online | Indexed CVEs: {r['indexed_cves']}")
        except Exception as e:
            st.error(f"Backend offline: {e}")

    if st.button("Sync Latest CISA KEV (Top 25)"):
        with st.spinner("Ingesting CISA KEV feed..."):
            try:
                r = requests.post(f"{API_URL}/ingest-kev?limit=25", timeout=120).json()
                st.success(f"Added {r['newly_indexed']} | Total: {r['total_indexed']}")
            except Exception as e:
                st.error(f"Sync failed: {e}")

tab1, tab2 = st.tabs(["🔍 Threat Intel & IAM/MITRE Mapper", "📦 Supply Chain / Dependency Auditor"])

with tab1:
    st.subheader("Active Vulnerability & Identity Risk Triage")
    query = st.text_input(
        "Ask a Threat Intelligence or CVE question:",
        value="Which recent vulnerabilities involve VPN, edge appliances, or authentication bypass?"
    )
    if st.button("Analyze Threat", type="primary"):
        with st.spinner("Querying ChromaDB & synthesizing via Llama 3.2:1b..."):
            try:
                res = requests.post(
                    f"{API_URL}/query",
                    json={"question": query, "top_k": 3},
                    timeout=120
                )
                res.raise_for_status()
                data = res.json()
                st.markdown(data["analysis"])
                with st.expander("📄 Matched CISA KEV Records"):
                    st.json(data["sources"])
            except Exception as e:
                st.error(f"Query failed: {e}")

with tab2:
    st.subheader("Software Supply Chain & AppSec Dependency Check")
    raw_deps = st.text_area(
        "Enter dependencies (one per line, format: package==version):",
        value="fastapi==0.115.0\nrequests==2.32.3\nopenssl==3.0.1"
    )
    if st.button("Audit Dependencies", type="primary"):
        deps = []
        for line in raw_deps.strip().splitlines():
            if "==" in line:
                pkg, ver = line.split("==", 1)
                deps.append({"package": pkg.strip(), "version": ver.strip()})
            elif line.strip():
                deps.append({"package": line.strip(), "version": "latest"})

        with st.spinner("Auditing dependencies against CISA KEV & AppSec rules..."):
            try:
                res = requests.post(
                    f"{API_URL}/audit-dependencies",
                    json={"dependencies": deps},
                    timeout=120
                )
                res.raise_for_status()
                data = res.json()
                st.markdown("### 🛡️ AppSec & Non-Human Identity Assessment")
                st.markdown(data["appsec_recommendations"])
                st.markdown("### 📋 Package Scan Results")
                st.json(data["results"])
            except Exception as e:
                st.error(f"Audit failed: {e}")