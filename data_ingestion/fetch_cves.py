import os
import shutil
import requests
from langchain_core.documents import Document
from langchain_community.embeddings import OllamaEmbeddings
from langchain_chroma import Chroma

def ingest_threat_data():
    db_path = "./vector_db"
    
    # Clear existing vector database so old 2015 CVEs don't mix with the newest ones
    if os.path.exists(db_path):
        print("[*] Clearing old ChromaDB index...")
        shutil.rmtree(db_path, ignore_errors=True)

    print("[*] Fetching latest CISA Known Exploited Vulnerabilities (KEV) feed...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    documents = []
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        all_vulns = data.get("vulnerabilities", [])
        # Sort chronologically by dateAdded (Newest to Oldest) and take the top 40
        vulnerabilities = sorted(
            all_vulns,
            key=lambda x: x.get("dateAdded", ""),
            reverse=True
        )[:40]
        
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "Unknown")
            vendor = vuln.get("vendorProject", "Unknown")
            product = vuln.get("product", "Unknown")
            name = vuln.get("vulnerabilityName", "")
            desc = vuln.get("shortDescription", "")
            action = vuln.get("requiredAction", "")
            date_added = vuln.get("dateAdded", "")
            ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
            
            content = (
                f"CVE ID: {cve_id}\n"
                f"Vendor/Product: {vendor} - {product}\n"
                f"Vulnerability Name: {name}\n"
                f"Date Added to CISA KEV: {date_added}\n"
                f"Known Ransomware Use: {ransomware}\n"
                f"Description: {desc}\n"
                f"Remediation / Required Action: {action}"
            )
            
            doc = Document(
                page_content=content,
                metadata={
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "date_added": date_added,
                    "ransomware": ransomware
                }
            )
            documents.append(doc)
            
        if vulnerabilities:
            newest_date = vulnerabilities[0].get("dateAdded", "Unknown")
            print(f"[+] Successfully parsed {len(documents)} latest CISA vulnerabilities (Newest from: {newest_date}).")
        
    except Exception as e:
        print(f"[!] Network fetch failed ({e}). Loading built-in critical CVE dataset...")
        fallback_cves = [
            {
                "cve_id": "CVE-2024-3094",
                "vendor": "XZ Utils",
                "product": "liblzma",
                "date_added": "2024-03-29",
                "ransomware": "Unknown",
                "content": "CVE ID: CVE-2024-3094\nVendor/Product: XZ Utils - liblzma\nDescription: Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0, permitting unauthorized remote SSH access.\nRemediation: Downgrade XZ Utils to an uncompromised version such as 5.4.6 immediately."
            },
            {
                "cve_id": "CVE-2024-21412",
                "vendor": "Microsoft",
                "product": "Windows",
                "date_added": "2024-02-13",
                "ransomware": "Known",
                "content": "CVE ID: CVE-2024-21412\nVendor/Product: Microsoft - Windows\nDescription: Internet Shortcut Files Security Feature Bypass Vulnerability bypassing SmartScreen checks.\nRemediation: Apply the latest Microsoft Windows cumulative security updates."
            }
        ]
        for item in fallback_cves:
            documents.append(Document(
                page_content=item["content"],
                metadata={
                    "cve_id": item["cve_id"],
                    "vendor": item["vendor"],
                    "product": item["product"],
                    "date_added": item["date_added"],
                    "ransomware": item["ransomware"]
                }
            ))

    print("[*] Generating embeddings with Ollama (nomic-embed-text) and storing in ChromaDB...")
    embeddings = OllamaEmbeddings(model="nomic-embed-text")
    
    Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        collection_name="threat_intelligence",
        persist_directory=db_path
    )
    print("[+] Ingestion complete! Latest threat data is indexed in ./vector_db")

if __name__ == "__main__":
    ingest_threat_data()