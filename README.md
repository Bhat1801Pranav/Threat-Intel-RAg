import os
import requests
import chromadb
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Local Threat Intelligence & AppSec RAG API", version="2.0")

OLLAMA_BASE_URL = "http://localhost:11434"
LLM_MODEL = "llama3.2:1b"
EMBED_MODEL = "nomic-embed-text"
CHROMA_PATH = "./vector_db"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

os.makedirs(CHROMA_PATH, exist_ok=True)
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection(name="cisa_kev_intel")

class QueryRequest(BaseModel):
    question: str
    top_k: int = 3

class DependencyItem(BaseModel):
    package: str
    version: Optional[str] = "latest"

class AuditRequest(BaseModel):
    dependencies: List[DependencyItem]

def get_embedding(text: str) -> List[float]:
    try:
        res = requests.post(
            f"{OLLAMA_BASE_URL}/api/embeddings",
            json={"model": EMBED_MODEL, "prompt": text, "keep_alive": "2m"},
            timeout=30,
        )
        res.raise_for_status()
        return res.json()["embedding"]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama Embedding Error: {str(e)}")

def generate_llm_response(prompt: str) -> str:
    try:
        res = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={
                "model": LLM_MODEL,
                "prompt": prompt,
                "stream": False,
                "keep_alive": "2m",
                "options": {
                    "num_ctx": 2048,
                    "temperature": 0.2,
                },
            },
            timeout=90,
        )
        res.raise_for_status()
        return res.json()["response"]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Ollama Generation Error: {str(e)}")

@app.get("/health")
def health_check():
    return {
        "status": "online",
        "indexed_cves": collection.count(),
        "llm_model": LLM_MODEL,
        "embed_model": EMBED_MODEL,
    }

    @app.post("/ingest-kev")
def ingest_cisa_kev(limit: int = 50):
    try:
        response = requests.get(CISA_KEV_URL, timeout=20)
        response.raise_for_status()
        vulns = response.json().get("vulnerabilities", [])
        vulns_sorted = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:limit]

        added_count = 0
        for item in vulns_sorted:
            cve_id = item.get("cveID")
            if not cve_id:
                continue

            existing = collection.get(ids=[cve_id])
            if existing and existing["ids"]:
                continue

            doc_text = (
                f"CVE ID: {cve_id} | Vendor: {item.get('vendorProject')} | "
                f"Product: {item.get('product')} | Vulnerability: {item.get('vulnerabilityName')} | "
                f"Date Added: {item.get('dateAdded')} | Description: {item.get('shortDescription')} | "
                f"Required Action: {item.get('requiredAction')} | "
                f"Known Ransomware Campaign Use: {item.get('knownRansomwareCampaignUse')}"
            )

            embedding = get_embedding(doc_text)
            collection.add(
                ids=[cve_id],
                embeddings=[embedding],
                documents=[doc_text],
                metadatas=[{
                    "cve_id": cve_id,
                    "vendor": item.get("vendorProject", "Unknown"),
                    "product": item.get("product", "Unknown"),
                    "date_added": item.get("dateAdded", ""),
                    "ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
                }],
            )
            added_count += 1

        return {
            "status": "success",
            "newly_indexed": added_count,
            "total_indexed": collection.count(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CISA KEV Ingestion Failed: {str(e)}")

@app.post("/query")
def query_threat_intel(req: QueryRequest):
    if collection.count() == 0:
        raise HTTPException(status_code=400, detail="Vector DB is empty. Run /ingest-kev first.")

    query_embedding = get_embedding(req.question)
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=min(req.top_k, collection.count()),
    )

    retrieved_docs = results["documents"][0]
    retrieved_meta = results["metadatas"][0]
    context_block = "\n\n".join(retrieved_docs)

    soc_prompt = f"""You are a Senior SOC & Identity Security Analyst. Analyze the retrieved CISA KEV vulnerability context below and answer the user's query concisely and accurately.

Retrieved Threat Intelligence Context:
{context_block}

User Query: {req.question}

Provide a structured assessment using these exact 4 sections:
1. **Threat Summary & Exploitation Status:** Summarize the matching CVE(s), affected vendor/product, and active exploitation/ransomware risk.
2. **MITRE ATT&CK Mapping:** Identify the most likely MITRE ATT&CK tactics and techniques (e.g., Initial Access T1190, Execution T1059, Privilege Escalation T1068, Credential Access T1552).
3. **IAM & Privilege Impact:** Explicitly evaluate whether this flaw enables Authentication Bypass, Privilege Escalation (Zero Standing Privilege / JIT risk), or Credential/API Key/Secret exposure. If none apply directly, state "Low direct IAM/PAM impact."
4. **Actionable Remediation:** Provide immediate patching steps, compensating controls, or privileged credential rotation guidance."""

    analysis = generate_llm_response(soc_prompt)
    return {
        "analysis": analysis,
        "sources": retrieved_meta,
    }

@app.post("/audit-dependencies")
def audit_dependencies(req: AuditRequest):
    if not req.dependencies:
        raise HTTPException(status_code=400, detail="No dependencies provided.")

    findings = []
    has_db = collection.count() > 0

    for dep in req.dependencies:
        pkg_query = f"{dep.package} {dep.version} vulnerability exploit"
        matched_cves = []

        if has_db:
            q_emb = get_embedding(pkg_query)
            res = collection.query(query_embeddings=[q_emb], n_results=min(2, collection.count()))
            for doc, meta, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0]):
                if dist < 1.1 or dep.package.lower() in doc.lower():
                    matched_cves.append({
                        "cve_id": meta["cve_id"],
                        "vendor": meta["vendor"],
                        "product": meta["product"],
                        "snippet": doc[:220] + "...",
                    })

        findings.append({
            "package": dep.package,
            "version": dep.version,
            "kev_matches": matched_cves,
            "risk_level": "HIGH (Active KEV Match)" if matched_cves else "LOW (No Local KEV Match)",
        })

    dep_summary_text = "\n".join(
        [f"- {f['package']} ({f['version']}): {f['risk_level']}" for f in findings]
    )
    appsec_prompt = f"""You are an Application Security (AppSec) Engineer. Review this software dependency scan result:

{dep_summary_text}

In 3 concise bullet points, provide:
1. Overall supply-chain risk posture.
2. Any API/Non-Human Identity (secrets, tokens, service account) precautions for these packages.
3. Recommended CI/CD verification step (e.g., SBOM generation, pinned versions)."""

    appsec_advice = generate_llm_response(appsec_prompt)
    return {
        "results": findings,
        "appsec_recommendations": appsec_advice,
    }