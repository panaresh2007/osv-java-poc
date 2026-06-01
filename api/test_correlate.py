"""
test_correlate.py
-----------------
Tests the /correlate endpoint using:
  - OSV Scanner output   (from your actual scan)
  - Semgrep sample       (sample_semgrep.json)
  - Gitleaks sample      (sample_gitleaks.json)

Usage:
  py -3.11 test_correlate.py
"""

import json
import sys
import os
import requests
from pathlib import Path

API_BASE  = "http://localhost:8000"
SCRIPT_DIR = Path(__file__).parent

# ── Load sample files ─────────────────────────
def load_json(path: str):
    p = Path(path)
    if not p.exists():
        print(f"  [SKIP] File not found: {path}")
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)

print("\n" + "="*60)
print("  OSV Correlate API — Test Script")
print("="*60)

# ── Check API is running ──────────────────────
print("\n[1/5] Checking API health...")
try:
    r = requests.get(f"{API_BASE}/health", timeout=5)
    health = r.json()
    print(f"  Status      : {health['status']}")
    print(f"  Platform    : {health['platform']}")
    print(f"  OSV Scanner : {health['osv_scanner']}")
except Exception as e:
    print(f"  [ERROR] API not running: {e}")
    print("  Start with: py -3.11 -m uvicorn main:app --reload --port 8000")
    sys.exit(1)

# ── Load files ────────────────────────────────
print("\n[2/5] Loading sample files...")

# OSV — try latest scan result first, fall back to inline sample
osv_path = None
results_dir = Path(r"C:\osv-poc\osv-results")
if results_dir.exists():
    folders = sorted(results_dir.glob("osv-java-poc_*"), reverse=True)
    for folder in folders:
        candidate = folder / "scan-direct.json"
        if candidate.exists():
            osv_path = str(candidate)
            break

osv_json = load_json(osv_path) if osv_path else None
if osv_json:
    print(f"  [OK] OSV JSON   : {osv_path}")
else:
    print("  [INFO] Using minimal OSV sample (no scan results found)")
    osv_json = {
        "results": [{
            "source": {"path": "pom.xml", "type": "lockfile"},
            "packages": [{
                "package": {"name": "commons-collections:commons-collections", "version": "3.2.1", "ecosystem": "Maven"},
                "vulnerabilities": [{
                    "id": "GHSA-fjq5-5j5f-mvxh",
                    "aliases": ["CVE-2015-7501"],
                    "summary": "Deserialization of Untrusted Data in Apache commons collections",
                    "database_specific": {"severity": "CRITICAL"},
                    "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.2"}]}]}]
                }]
            }]
        }]
    }

semgrep_json  = load_json(str(SCRIPT_DIR / "sample_semgrep.json"))
gitleaks_json = load_json(str(SCRIPT_DIR / "sample_gitleaks.json"))

if semgrep_json:  print(f"  [OK] Semgrep   : sample_semgrep.json ({len(semgrep_json.get('results',[]))} findings)")
if gitleaks_json: print(f"  [OK] Gitleaks  : sample_gitleaks.json ({len(gitleaks_json)} findings)")

# ── Call /correlate ───────────────────────────
print("\n[3/5] Calling POST /correlate...")

payload = {
    "repo_url":      "https://github.com/panaresh2007/osv-java-poc",
    "project_name":  "osv-java-poc",
    "osv_json":      osv_json,
    "semgrep_json":  semgrep_json,
    "gitleaks_json": gitleaks_json,
}

try:
    r = requests.post(f"{API_BASE}/correlate", json=payload, timeout=30)
    if r.status_code != 200:
        print(f"  [ERROR] HTTP {r.status_code}: {r.text[:500]}")
        sys.exit(1)
    result = r.json()
except Exception as e:
    print(f"  [ERROR] {e}")
    sys.exit(1)

print(f"  [OK] Response received")

# ── Print summary ─────────────────────────────
print("\n[4/5] Results summary...")
print(f"\n  {'='*50}")
print(f"  Project       : {result['project_name']}")
print(f"  Generated at  : {result['generated_at']}")
print(f"  Total findings: {result['total_findings']}")
print(f"\n  By tool:")
for tool, count in result['by_tool'].items():
    print(f"    {tool:<20} : {count}")
print(f"\n  By severity:")
for sev, count in sorted(result['by_severity'].items(),
    key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x[0],5)):
    print(f"    {sev:<12} : {count}")
print(f"\n  By category:")
for cat, count in result['by_category'].items():
    print(f"    {cat:<12} : {count}")
print(f"  {'='*50}")

# ── Show top 5 findings ───────────────────────
print(f"\n  Top 5 findings:")
for i, f in enumerate(result['findings'][:5], 1):
    cve = f.get('cve') or ''
    pkg = f.get('package') or f.get('file_path') or ''
    print(f"  {i}. [{f['severity']:<8}] [{f['category']}] {f['title'][:50]}")
    print(f"     Tool: {f['tool']}  |  {pkg}  {cve}")

# ── Save SARIF ────────────────────────────────
print("\n[5/5] Saving output files...")

sarif_path    = SCRIPT_DIR / "findings.sarif"
findings_path = SCRIPT_DIR / "findings.json"

with open(sarif_path, "w", encoding="utf-8") as f:
    json.dump(result["sarif"], f, indent=2)
print(f"  [OK] SARIF saved    : {sarif_path}")

with open(findings_path, "w", encoding="utf-8") as f:
    json.dump(result["findings"], f, indent=2)
print(f"  [OK] Findings saved : {findings_path}")

# ── Also test /correlate/sarif download ──────
print("\n  Testing /correlate/sarif download...")
r2 = requests.post(f"{API_BASE}/correlate/sarif", json=payload, timeout=30)
if r2.status_code == 200:
    sarif_dl = SCRIPT_DIR / "osv-java-poc.sarif"
    with open(sarif_dl, "wb") as f:
        f.write(r2.content)
    print(f"  [OK] SARIF download : {sarif_dl}")
else:
    print(f"  [WARN] SARIF download failed: {r2.status_code}")

print("\n" + "="*60)
print("  TEST COMPLETE")
print("="*60)
print(f"""
  Files generated:
    findings.sarif      ← upload to GitHub/ADO/Defect Dojo
    findings.json       ← canonical findings for downstream tools
    osv-java-poc.sarif  ← direct download from /correlate/sarif

  Next steps:
    GitHub  : Upload findings.sarif via codeql-action/upload-sarif
    ADO     : Publish as build artifact + security scan task
    VS Code : Open findings.sarif with SARIF Viewer extension
""")
