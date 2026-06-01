"""
OSV Scanner CVE Detection API
FastAPI application — platform independent (Windows / Linux / Mac)

Endpoints:
  POST /scan          — scan a GitHub/ADO repo, returns CVE JSON
  GET  /scan/{job_id} — get status/results of a scan
  GET  /scan/{job_id}/csv — download results as CSV
  GET  /health        — health check
  GET  /docs          — auto-generated Swagger UI
"""

import asyncio
import csv
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Union

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl

# ─────────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────────
app = FastAPI(
    title="OSV Scanner CVE Detection API",
    description="Scan any GitHub or ADO repository for CVEs using OSV Scanner. "
                "Supports direct dependency scanning (pom.xml, package-lock.json etc.) "
                "and full transitive dependency scanning via CycloneDX SBOM (Maven).",
    version="1.0.0",
    contact={"name": "OSV POC"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  Configuration — auto-detect OS paths
# ─────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"

def find_tool(name: str, windows_path: str) -> Optional[str]:
    """Find a tool — use known Windows path or search PATH on Linux/Mac."""
    if IS_WINDOWS:
        path = Path(windows_path)
        if path.exists():
            return str(path)
    # Search PATH
    found = shutil.which(name)
    return found

OSV_EXE   = find_tool("osv-scanner", r"C:\osv-poc\osv-scanner.exe")
MVN_EXE   = find_tool("mvn", r"C:\osv-poc\maven\apache-maven-3.9.6\bin\mvn.cmd")
GIT_EXE   = find_tool("git", "git")
JAVA_HOME = os.environ.get("JAVA_HOME", r"C:\Program Files\Microsoft\jdk-17.0.19.10-hotspot")

RESULTS_DIR = Path("osv-api-results")
RESULTS_DIR.mkdir(exist_ok=True)

# In-memory job store
jobs: dict = {}

# ─────────────────────────────────────────────
#  Models
# ─────────────────────────────────────────────
class ScanStatus(str, Enum):
    PENDING    = "pending"
    CLONING    = "cloning"
    SCANNING   = "scanning"
    GENERATING = "generating_sbom"
    PARSING    = "parsing"
    DONE       = "done"
    FAILED     = "failed"

class ScanRequest(BaseModel):
    repo_url: str
    include_transitive: bool = True

    class Config:
        json_schema_extra = {
            "example": {
                "repo_url": "https://github.com/panaresh2007/osv-java-poc",
                "include_transitive": True
            }
        }

class CVEFinding(BaseModel):
    scan_type:     str
    severity:      str
    package:       str
    version:       str
    cve:           str
    osv_id:        str
    summary:       str
    fixed_version: str
    osv_link:      str
    nvd_link:      str

class ScanSummary(BaseModel):
    total:    int
    critical: int
    high:     int
    medium:   int
    low:      int
    unknown:  int

class ScanResult(BaseModel):
    job_id:         str
    status:         ScanStatus
    repo_url:       str
    started_at:     str
    completed_at:   Optional[str] = None
    duration_secs:  Optional[float] = None
    error:          Optional[str] = None
    summary:        Optional[ScanSummary] = None
    findings:       Optional[List[CVEFinding]] = None

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def run_cmd(cmd: list, cwd: str = None, timeout: int = 120) -> tuple[int, str, str]:
    """Run a subprocess command, return (exit_code, stdout, stderr)."""
    env = os.environ.copy()
    if IS_WINDOWS and JAVA_HOME:
        env["JAVA_HOME"] = JAVA_HOME
        env["PATH"] = f"{JAVA_HOME}\\bin;{env.get('PATH', '')}"

    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    return result.returncode, result.stdout, result.stderr


def get_severity(vuln: dict) -> str:
    """Extract severity from OSV vulnerability object."""
    db_sev = (vuln.get("database_specific") or {}).get("severity", "")
    if db_sev:
        return db_sev.upper()
    for s in vuln.get("severity", []):
        score_str = s.get("score", "").split("/")[-1]
        try:
            score = float(score_str)
            if score >= 9.0: return "CRITICAL"
            if score >= 7.0: return "HIGH"
            if score >= 4.0: return "MEDIUM"
            return "LOW"
        except ValueError:
            pass
    return "UNKNOWN"


def get_fixed_version(vuln: dict) -> str:
    """Extract the fixed version from OSV vulnerability ranges."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return "No fix yet"


def parse_osv_json(raw: dict, scan_type: str) -> List[CVEFinding]:
    """Parse raw OSV JSON into a list of CVEFinding objects."""
    findings = []
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    for result in raw.get("results", []):
        for pkg in result.get("packages", []):
            package = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                cve = next(
                    (a for a in vuln.get("aliases", []) if a.startswith("CVE-")),
                    "N/A"
                )
                sev   = get_severity(vuln)
                fixed = get_fixed_version(vuln)
                osv_id = vuln.get("id", "")

                findings.append(CVEFinding(
                    scan_type     = scan_type,
                    severity      = sev,
                    package       = package.get("name", ""),
                    version       = package.get("version", ""),
                    cve           = cve,
                    osv_id        = osv_id,
                    summary       = vuln.get("summary", ""),
                    fixed_version = fixed,
                    osv_link      = f"https://osv.dev/vulnerability/{osv_id}",
                    nvd_link      = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve != "N/A" else "N/A",
                ))

    findings.sort(key=lambda x: sev_order.get(x.severity, 4))
    return findings


def build_summary(findings: List[CVEFinding]) -> ScanSummary:
    return ScanSummary(
        total    = len(findings),
        critical = sum(1 for f in findings if f.severity == "CRITICAL"),
        high     = sum(1 for f in findings if f.severity == "HIGH"),
        medium   = sum(1 for f in findings if f.severity == "MEDIUM"),
        low      = sum(1 for f in findings if f.severity == "LOW"),
        unknown  = sum(1 for f in findings if f.severity == "UNKNOWN"),
    )


def findings_to_csv(findings: List[CVEFinding]) -> str:
    """Convert findings list to CSV string."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "ScanType", "Severity", "Package", "Version",
        "CVE", "OSV_ID", "Summary", "Fixed_Version", "OSV_Link", "NVD_Link"
    ])
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "ScanType":     f.scan_type,
            "Severity":     f.severity,
            "Package":      f.package,
            "Version":      f.version,
            "CVE":          f.cve,
            "OSV_ID":       f.osv_id,
            "Summary":      f.summary,
            "Fixed_Version":f.fixed_version,
            "OSV_Link":     f.osv_link,
            "NVD_Link":     f.nvd_link,
        })
    return output.getvalue()


def detect_lockfiles(repo_dir: Path) -> list:
    """Detect all supported lock files in the repo."""
    supported = [
        "pom.xml",
        "package-lock.json",
        "yarn.lock",
        "requirements.txt",
        "Pipfile.lock",
        "go.sum",
        "Cargo.lock",
        "Gemfile.lock",
    ]
    found = []
    for f in supported:
        if (repo_dir / f).exists():
            found.append(str(repo_dir / f))
    return found


# ─────────────────────────────────────────────
#  Background scan task
# ─────────────────────────────────────────────
async def run_scan(job_id: str, repo_url: str, include_transitive: bool):
    """Main scan logic — runs as a background task."""
    job       = jobs[job_id]
    work_dir  = RESULTS_DIR / job_id / "repo"
    start     = datetime.now()
    all_findings: List[CVEFinding] = []

    try:
        # ── 1. Clone repo ──────────────────────────
        job["status"] = ScanStatus.CLONING
        work_dir.mkdir(parents=True, exist_ok=True)

        code, out, err = run_cmd(
            [GIT_EXE or "git", "clone", repo_url, str(work_dir)],
            timeout=120
        )
        if code != 0:
            raise Exception(f"Git clone failed: {err}")

        # ── 2. Detect lock files ───────────────────
        lockfiles = detect_lockfiles(work_dir)
        if not lockfiles:
            raise Exception("No supported lock files found in repository.")

        job["status"]    = ScanStatus.SCANNING
        job["lockfiles"] = [Path(f).name for f in lockfiles]
        is_maven         = any("pom.xml" in f for f in lockfiles)

        # ── 3. Direct scan ─────────────────────────
        direct_json = RESULTS_DIR / job_id / "direct.json"
        lf_args = []
        for lf in lockfiles:
            lf_args += ["--lockfile", lf]

        code, out, err = run_cmd(
            [OSV_EXE, "scan", "source"] + lf_args +
            ["--format", "json", "--output-file", str(direct_json)],
            timeout=120
        )

        if direct_json.exists():
            raw = json.loads(direct_json.read_text(encoding="utf-8"))
            all_findings += parse_osv_json(raw, "Direct")

        # ── 4. Transitive scan via SBOM ────────────
        if include_transitive and is_maven and MVN_EXE:
            job["status"] = ScanStatus.GENERATING

            bom_json = work_dir / "target" / "bom.json"

            # Check for committed bom.json first
            committed_bom = work_dir / "bom.json"
            if committed_bom.exists():
                bom_json = committed_bom
            else:
                # Generate via Maven
                code, out, err = run_cmd(
                    [MVN_EXE,
                     "org.cyclonedx:cyclonedx-maven-plugin:2.7.9:makeAggregateBom",
                     "-DoutputFormat=json"],
                    cwd=str(work_dir),
                    timeout=180
                )

            if bom_json.exists():
                transitive_json = RESULTS_DIR / job_id / "transitive.json"
                code, out, err = run_cmd(
                    [OSV_EXE, "scan", "source",
                     "-L", str(bom_json),
                     "--format", "json",
                     "--output-file", str(transitive_json)],
                    timeout=120
                )
                if transitive_json.exists():
                    raw = json.loads(transitive_json.read_text(encoding="utf-8"))
                    all_findings += parse_osv_json(raw, "Transitive")

        # ── 5. Save results ────────────────────────
        job["status"]       = ScanStatus.PARSING
        job["findings"]     = [f.dict() for f in all_findings]
        job["summary"]      = build_summary(all_findings).dict()
        job["status"]       = ScanStatus.DONE
        job["completed_at"] = datetime.now().isoformat()
        job["duration_secs"]= (datetime.now() - start).total_seconds()

    except Exception as e:
        job["status"] = ScanStatus.FAILED
        job["error"]  = str(e)
        job["completed_at"] = datetime.now().isoformat()
    finally:
        # Cleanup cloned repo
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


# ─────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────
@app.get("/health", tags=["System"])
def health():
    """Health check — also shows tool availability."""
    return {
        "status":      "ok",
        "platform":    platform.system(),
        "osv_scanner": OSV_EXE or "not found",
        "maven":       MVN_EXE or "not found",
        "git":         GIT_EXE or "not found",
        "java_home":   JAVA_HOME or "not set",
    }


@app.post("/scan", response_model=ScanResult, status_code=202, tags=["Scan"])
async def start_scan(
    background_tasks: BackgroundTasks,
    repo_url: Optional[str] = None,
    include_transitive: bool = True,
    request: Optional[ScanRequest] = None,
):
    """
    Start a CVE scan on a repository.

    You can pass the repo URL in **three ways**:

    **Option 1 — Query parameter (simplest):**
    ```
    POST /scan?repo_url=https://github.com/your-org/your-repo
    POST /scan?repo_url=https://github.com/your-org/your-repo&include_transitive=false
    ```

    **Option 2 — Request body (JSON):**
    ```json
    { "repo_url": "https://github.com/your-org/your-repo", "include_transitive": true }
    ```

    **Option 3 — Both** (query param takes priority)

    Returns a job_id immediately — poll GET /scan/{job_id} for results.
    """
    if not OSV_EXE:
        raise HTTPException(status_code=503, detail="osv-scanner not found. Install from https://github.com/google/osv-scanner/releases")
    if not GIT_EXE:
        raise HTTPException(status_code=503, detail="git not found. Install Git first.")

    # Resolve repo_url — query param takes priority over body
    final_url = repo_url or (request.repo_url if request else None)
    final_transitive = include_transitive if repo_url else (request.include_transitive if request else True)

    if not final_url:
        raise HTTPException(
            status_code=422,
            detail="repo_url is required. Pass as query param (?repo_url=...) or in request body."
        )

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id":       job_id,
        "status":       ScanStatus.PENDING,
        "repo_url":     final_url,
        "started_at":   datetime.now().isoformat(),
        "completed_at": None,
        "duration_secs":None,
        "error":        None,
        "summary":      None,
        "findings":     None,
    }

    (RESULTS_DIR / job_id).mkdir(parents=True, exist_ok=True)
    background_tasks.add_task(run_scan, job_id, final_url, final_transitive)

    return ScanResult(**jobs[job_id])


@app.get("/scan/{job_id}", response_model=ScanResult, tags=["Scan"])
def get_scan(job_id: str):
    """
    Get scan status and results.

    - While running: returns current status (pending/cloning/scanning/generating_sbom/parsing)
    - When done: returns full CVE findings list with summary
    - On failure: returns error message
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    job = jobs[job_id]
    return ScanResult(
        job_id        = job["job_id"],
        status        = job["status"],
        repo_url      = job["repo_url"],
        started_at    = job["started_at"],
        completed_at  = job.get("completed_at"),
        duration_secs = job.get("duration_secs"),
        error         = job.get("error"),
        summary       = ScanSummary(**job["summary"]) if job.get("summary") else None,
        findings      = [CVEFinding(**f) for f in job["findings"]] if job.get("findings") else None,
    )


@app.get("/scan/{job_id}/csv", tags=["Scan"])
def download_csv(job_id: str):
    """
    Download CVE findings as a CSV file.
    Only available when scan status is 'done'.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")

    job = jobs[job_id]
    if job["status"] != ScanStatus.DONE:
        raise HTTPException(status_code=400, detail=f"Scan not complete yet. Status: {job['status']}")
    if not job.get("findings"):
        raise HTTPException(status_code=404, detail="No findings to download.")

    findings = [CVEFinding(**f) for f in job["findings"]]
    csv_content = findings_to_csv(findings)

    repo_name = job["repo_url"].rstrip("/").split("/")[-1]
    filename  = f"{repo_name}_cve_report.csv"

    return StreamingResponse(
        io.BytesIO(csv_content.encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/scan/{job_id}/summary", tags=["Scan"])
def get_summary(job_id: str):
    """Get just the CVE summary counts without full findings list."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    job = jobs[job_id]
    if job["status"] != ScanStatus.DONE:
        raise HTTPException(status_code=400, detail=f"Scan not complete. Status: {job['status']}")
    return {
        "job_id":   job_id,
        "repo_url": job["repo_url"],
        "summary":  job["summary"],
        "duration": job.get("duration_secs"),
    }


@app.get("/jobs", tags=["System"])
def list_jobs():
    """List all scan jobs with their current status."""
    return [
        {
            "job_id":    j["job_id"],
            "status":    j["status"],
            "repo_url":  j["repo_url"],
            "started_at":j["started_at"],
            "total_cves":j["summary"]["total"] if j.get("summary") else None,
        }
        for j in jobs.values()
    ]


@app.delete("/scan/{job_id}", tags=["Scan"])
def delete_job(job_id: str):
    """Delete a scan job and its results."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")
    del jobs[job_id]
    result_dir = RESULTS_DIR / job_id
    if result_dir.exists():
        shutil.rmtree(result_dir, ignore_errors=True)
    return {"deleted": job_id}


# ─────────────────────────────────────────────
#  CANONICAL / CORRELATE  — /correlate
#  Accepts OSV + Semgrep + Gitleaks JSON
#  Outputs unified SARIF 2.1.0
# ─────────────────────────────────────────────

class ToolName(str, Enum):
    OSV      = "osv-scanner"
    SEMGREP  = "semgrep"
    GITLEAKS = "gitleaks"

class CorrelateRequest(BaseModel):
    osv_json:      Optional[dict] = None   # raw OSV scanner JSON output
    semgrep_json:  Optional[dict] = None   # raw Semgrep JSON output
    gitleaks_json: Optional[Union[list, dict]] = None   # raw Gitleaks JSON output (list or dict)
    repo_url:      Optional[str]  = None   # optional — added to SARIF metadata
    project_name:  Optional[str]  = None   # optional — added to SARIF metadata

    class Config:
        json_schema_extra = {
            "example": {
                "repo_url":     "https://github.com/panaresh2007/osv-java-poc",
                "project_name": "osv-java-poc",
                "osv_json":     {"results": []},
                "semgrep_json": {"results": []},
                "gitleaks_json":[]
            }
        }

class CanonicalFinding(BaseModel):
    """Unified finding schema — source-agnostic."""
    id:           str            # unique finding ID
    tool:         str            # osv-scanner | semgrep | gitleaks
    category:     str            # SCA | SAST | SECRET
    severity:     str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title:        str            # short description
    description:  str            # full description
    cve:          Optional[str]  # CVE ID if applicable
    cwe:          Optional[str]  # CWE ID if applicable
    package:      Optional[str]  # affected package (SCA)
    version:      Optional[str]  # affected version (SCA)
    fixed_version:Optional[str]  # fix version (SCA)
    file_path:    Optional[str]  # source file (SAST/SECRET)
    line_start:   Optional[int]  # line number (SAST/SECRET)
    line_end:     Optional[int]  # line number end (SAST/SECRET)
    rule_id:      Optional[str]  # tool rule/check ID
    fingerprint:  Optional[str]  # unique hash for dedup
    osv_link:     Optional[str]  # link to OSV/NVD
    tags:         List[str]      # owasp, cwe, tool-specific tags

class CorrelateResult(BaseModel):
    project_name:    str
    repo_url:        Optional[str]
    generated_at:    str
    total_findings:  int
    by_tool:         dict
    by_severity:     dict
    by_category:     dict
    findings:        List[CanonicalFinding]
    sarif:           dict          # full SARIF 2.1.0 output


def sev_to_sarif_level(sev: str) -> str:
    """Map severity to SARIF notification level."""
    return {
        "CRITICAL": "error",
        "HIGH":     "error",
        "MEDIUM":   "warning",
        "MODERATE": "warning",
        "LOW":      "note",
        "INFO":     "none",
    }.get(sev.upper(), "warning")


def normalise_severity(sev: str) -> str:
    """Normalise all severity strings to standard set."""
    s = sev.upper()
    if s in ("CRITICAL",):         return "CRITICAL"
    if s in ("HIGH",):             return "HIGH"
    if s in ("MEDIUM", "MODERATE","WARN", "WARNING"): return "MEDIUM"
    if s in ("LOW", "NOTE"):       return "LOW"
    return "INFO"


# ── OSV parser ────────────────────────────────
def parse_osv_to_canonical(osv_raw: dict) -> List[CanonicalFinding]:
    findings = []
    for result in osv_raw.get("results", []):
        for pkg in result.get("packages", []):
            package = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                cve   = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), None)
                cwe   = next((a for a in vuln.get("aliases", []) if a.startswith("CWE-")), None)
                sev   = get_severity(vuln)
                fixed = get_fixed_version(vuln)
                osv_id = vuln.get("id", "")
                pkg_name = package.get("name", "")
                pkg_ver  = package.get("version", "")

                # build fingerprint
                fp = f"osv::{pkg_name}::{pkg_ver}::{osv_id}"

                findings.append(CanonicalFinding(
                    id           = f"OSV-{osv_id}",
                    tool         = "osv-scanner",
                    category     = "SCA",
                    severity     = normalise_severity(sev),
                    title        = vuln.get("summary", f"Vulnerability in {pkg_name}"),
                    description  = vuln.get("details", vuln.get("summary", "")),
                    cve          = cve,
                    cwe          = cwe,
                    package      = pkg_name,
                    version      = pkg_ver,
                    fixed_version= fixed if fixed != "No fix yet" else None,
                    file_path    = None,
                    line_start   = None,
                    line_end     = None,
                    rule_id      = osv_id,
                    fingerprint  = fp,
                    osv_link     = f"https://osv.dev/vulnerability/{osv_id}",
                    tags         = (
                        ["SCA", "dependency"] +
                        ([cve] if cve else []) +
                        ([cwe] if cwe else []) +
                        ["OWASP-A06"]
                    ),
                ))
    return findings


# ── Semgrep parser ────────────────────────────
def parse_semgrep_to_canonical(semgrep_raw: dict) -> List[CanonicalFinding]:
    findings = []
    for r in semgrep_raw.get("results", []):
        sev      = r.get("extra", {}).get("severity", "WARNING")
        rule_id  = r.get("check_id", "unknown")
        path     = r.get("path", "")
        start    = r.get("start", {})
        end      = r.get("end", {})
        message  = r.get("extra", {}).get("message", "")
        metadata = r.get("extra", {}).get("metadata", {})

        # extract CWE / CVE from metadata
        cwe_list = metadata.get("cwe", [])
        cwe      = cwe_list[0] if cwe_list else None
        cve      = metadata.get("cve", None)

        # OWASP tags
        owasp_tags = metadata.get("owasp", [])
        if isinstance(owasp_tags, str):
            owasp_tags = [owasp_tags]

        fp = f"semgrep::{rule_id}::{path}::{start.get('line', 0)}"

        findings.append(CanonicalFinding(
            id           = f"SEMGREP-{abs(hash(fp)) % 100000:05d}",
            tool         = "semgrep",
            category     = "SAST",
            severity     = normalise_severity(sev),
            title        = rule_id.split(".")[-1].replace("-", " ").title(),
            description  = message,
            cve          = cve,
            cwe          = cwe,
            package      = None,
            version      = None,
            fixed_version= None,
            file_path    = path,
            line_start   = start.get("line"),
            line_end     = end.get("line"),
            rule_id      = rule_id,
            fingerprint  = fp,
            osv_link     = None,
            tags         = ["SAST"] + owasp_tags + ([cwe] if cwe else []),
        ))
    return findings


# ── Gitleaks parser ───────────────────────────
def parse_gitleaks_to_canonical(gitleaks_raw) -> List[CanonicalFinding]:
    findings = []
    # Gitleaks outputs a list directly
    items = gitleaks_raw if isinstance(gitleaks_raw, list) else gitleaks_raw.get("findings", [])

    for r in items:
        rule_id  = r.get("RuleID",      r.get("ruleID",      "secret"))
        desc     = r.get("Description", r.get("description", "Secret detected"))
        path     = r.get("File",        r.get("file",        ""))
        line     = r.get("StartLine",   r.get("startLine",   0))
        commit   = r.get("Commit",      r.get("commit",      ""))
        secret   = r.get("Secret",      r.get("secret",      ""))
        author   = r.get("Author",      r.get("author",      ""))

        fp = f"gitleaks::{rule_id}::{path}::{line}"

        # Redact secret value from description
        safe_desc = f"{desc} — detected in {path} at line {line}"
        if commit:
            safe_desc += f" (commit: {commit[:8]})"

        findings.append(CanonicalFinding(
            id           = f"GITLEAKS-{abs(hash(fp)) % 100000:05d}",
            tool         = "gitleaks",
            category     = "SECRET",
            severity     = "HIGH",   # secrets are always high by default
            title        = f"Secret detected: {rule_id.replace('-', ' ').title()}",
            description  = safe_desc,
            cve          = None,
            cwe          = "CWE-798",  # hardcoded credentials
            package      = None,
            version      = None,
            fixed_version= None,
            file_path    = path,
            line_start   = line,
            line_end     = line,
            rule_id      = rule_id,
            fingerprint  = fp,
            osv_link     = None,
            tags         = ["SECRET", "CWE-798", "OWASP-A02", "credential"],
        ))
    return findings


# ── SARIF 2.1.0 builder ───────────────────────
def build_sarif(
    findings: List[CanonicalFinding],
    project_name: str,
    repo_url: Optional[str],
) -> dict:
    """Build a SARIF 2.1.0 document from canonical findings."""

    # Group rules by tool
    tools_rules: dict = {}
    for f in findings:
        if f.tool not in tools_rules:
            tools_rules[f.tool] = {}
        if f.rule_id and f.rule_id not in tools_rules[f.tool]:
            tools_rules[f.tool][f.rule_id] = {
                "id":   f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.description[:1000] if f.description else f.title},
                "properties": {
                    "tags":     f.tags,
                    "category": f.category,
                },
                "helpUri": f.osv_link or "",
            }

    # Build runs per tool
    runs = []
    for tool_name, rules in tools_rules.items():
        tool_findings = [f for f in findings if f.tool == tool_name]

        results = []
        for f in tool_findings:
            result = {
                "ruleId":  f.rule_id or f.id,
                "level":   sev_to_sarif_level(f.severity),
                "message": {"text": f.description or f.title},
                "properties": {
                    "severity":    f.severity,
                    "category":    f.category,
                    "fingerprint": f.fingerprint,
                    "tags":        f.tags,
                },
            }

            # Add CVE / CWE
            if f.cve:
                result["properties"]["cve"] = f.cve
            if f.cwe:
                result["properties"]["cwe"] = f.cwe
            if f.package:
                result["properties"]["package"] = f.package
                result["properties"]["version"]  = f.version
            if f.fixed_version:
                result["properties"]["fixedVersion"] = f.fixed_version

            # Location
            if f.file_path:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": f.line_start or 1,
                            "endLine":   f.line_end   or f.line_start or 1,
                        }
                    }
                }]
            elif f.package:
                # SCA findings — use package as location
                result["locations"] = [{
                    "logicalLocations": [{
                        "name":            f.package,
                        "kind":            "package",
                        "fullyQualifiedName": f"{f.package}@{f.version}",
                    }]
                }]

            results.append(result)

        run = {
            "tool": {
                "driver": {
                    "name":            tool_name,
                    "informationUri":  f"https://github.com/google/osv-scanner" if tool_name == "osv-scanner"
                                       else f"https://semgrep.dev" if tool_name == "semgrep"
                                       else "https://github.com/gitleaks/gitleaks",
                    "rules": list(rules.values()),
                }
            },
            "results":    results,
            "invocations": [{
                "executionSuccessful": True,
                "commandLine": f"{tool_name} scan",
            }],
        }

        if repo_url:
            run["versionControlProvenance"] = [{
                "repositoryUri": repo_url,
                "branch":        "main",
            }]

        runs.append(run)

    sarif = {
        "$schema":  "https://json.schemastore.org/sarif-2.1.0.json",
        "version":  "2.1.0",
        "runs":     runs,
        "properties": {
            "projectName":   project_name,
            "generatedAt":   datetime.now().isoformat(),
            "totalFindings": len(findings),
        }
    }
    return sarif


# ── /correlate endpoint ───────────────────────
@app.post("/correlate", tags=["Correlate"])
async def correlate(request: CorrelateRequest):
    """
    Merge OSV Scanner + Semgrep + Gitleaks outputs into a unified canonical format.

    **Input:** Raw JSON output from any combination of the three tools.

    **Output:** 
    - Unified findings list (canonical schema)
    - Full **SARIF 2.1.0** document — accepted by GitHub Advanced Security, 
      Azure DevOps, SonarQube, Defect Dojo, and all prioritization/reachability tools

    **Supported tools:**
    - `osv_json` — OSV Scanner raw JSON (`--format json` output)
    - `semgrep_json` — Semgrep raw JSON (`--format json` output)
    - `gitleaks_json` — Gitleaks raw JSON (`--report-format json` output)

    You can pass one, two, or all three — any combination works.
    """
    if not any([request.osv_json, request.semgrep_json, request.gitleaks_json]):
        raise HTTPException(
            status_code=422,
            detail="At least one of osv_json, semgrep_json, or gitleaks_json is required."
        )

    all_findings: List[CanonicalFinding] = []

    # Parse each tool's output
    if request.osv_json:
        osv_findings = parse_osv_to_canonical(request.osv_json)
        all_findings += osv_findings

    if request.semgrep_json:
        semgrep_findings = parse_semgrep_to_canonical(request.semgrep_json)
        all_findings += semgrep_findings

    if request.gitleaks_json:
        gitleaks_findings = parse_gitleaks_to_canonical(request.gitleaks_json)
        all_findings += gitleaks_findings

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_order.get(x.severity, 4))

    # Stats
    by_tool     = {}
    by_severity = {}
    by_category = {}
    for f in all_findings:
        by_tool[f.tool]         = by_tool.get(f.tool, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    project_name = request.project_name or (
        request.repo_url.rstrip("/").split("/")[-1] if request.repo_url else "unknown"
    )

    # Build SARIF
    sarif = build_sarif(all_findings, project_name, request.repo_url)

    return CorrelateResult(
        project_name   = project_name,
        repo_url       = request.repo_url,
        generated_at   = datetime.now().isoformat(),
        total_findings = len(all_findings),
        by_tool        = by_tool,
        by_severity    = by_severity,
        by_category    = by_category,
        findings       = all_findings,
        sarif          = sarif,
    )


@app.post("/correlate/sarif", tags=["Correlate"])
async def correlate_sarif_only(request: CorrelateRequest):
    """
    Same as /correlate but returns **only the SARIF 2.1.0 file** as a download.
    Upload directly to GitHub Advanced Security or Azure DevOps.
    """
    if not any([request.osv_json, request.semgrep_json, request.gitleaks_json]):
        raise HTTPException(status_code=422, detail="At least one tool output is required.")

    all_findings: List[CanonicalFinding] = []
    if request.osv_json:      all_findings += parse_osv_to_canonical(request.osv_json)
    if request.semgrep_json:  all_findings += parse_semgrep_to_canonical(request.semgrep_json)
    if request.gitleaks_json: all_findings += parse_gitleaks_to_canonical(request.gitleaks_json)

    project_name = request.project_name or "project"
    sarif = build_sarif(all_findings, project_name, request.repo_url)
    sarif_bytes = json.dumps(sarif, indent=2).encode("utf-8")

    return StreamingResponse(
        io.BytesIO(sarif_bytes),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={project_name}.sarif"}
    )
