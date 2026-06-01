\# OSV CVE Detection Platform — POC



End-to-end CVE detection platform using OSV Scanner, with SAST and Secrets correlation.



\## Repository structure



osv-java-poc/

├── pom.xml                      ← Vulnerable Java app (intentional CVEs)

├── src/                         ← Java source code

├── api/

│   ├── main.py                  ← FastAPI CVE Detection API

│   ├── requirements.txt         ← Python dependencies

│   ├── test\_correlate.py        ← Correlate endpoint test

│   ├── API\_GUIDE.md             ← API usage guide

│   ├── SETUP\_GUIDE.md           ← Full setup instructions

│   └── samples/

│       ├── sample\_semgrep.json  ← Sample Semgrep output

│       └── sample\_gitleaks.json ← Sample Gitleaks output

└── scripts/

├── osv-scan.bat             ← Windows batch scan tool

├── parse-osv.ps1            ← CSV parser

├── analyse-and-fix.bat      ← Auto-fix tool

└── analyse-and-fix.ps1      ← Fix + HTML report



\## Quick start



See \[api/SETUP\_GUIDE.md](api/SETUP\_GUIDE.md) for full setup instructions.



\## API endpoints



See \[api/API\_GUIDE.md](api/API\_GUIDE.md) for full API documentation.

