# OSV Scanner CVE Detection POC — Vulnerable Java App

> **⚠️ WARNING: This project is intentionally vulnerable. For educational/POC use only. Never use these dependency versions in production.**

## What this is

A Java Maven project with deliberately outdated dependencies, each carrying real CVEs. Used to demonstrate OSV Scanner CVE detection.

## CVEs included

| Dependency | Version | CVE | Severity | Description |
|---|---|---|---|---|
| log4j-core | 2.14.1 | CVE-2021-44228 | 🔴 CRITICAL 10.0 | Log4Shell — JNDI RCE |
| spring-webmvc | 5.3.17 | CVE-2022-22965 | 🔴 CRITICAL 9.8 | Spring4Shell RCE |
| commons-collections | 3.2.1 | CVE-2015-7501 | 🔴 CRITICAL 9.8 | Deserialization RCE |
| spring-web | 5.3.17 | CVE-2016-1000027 | 🔴 CRITICAL 9.8 | HttpInvoker RCE |
| maven-core | 3.8.1 | CVE-2021-26291 | 🔴 CRITICAL 9.1 | Build hijacking |
| commons-beanutils | 1.9.3 | CVE-2019-10086 | 🟠 HIGH 7.3 | ClassLoader attack |
| jackson-databind | 2.13.2 | CVE-2022-42003 | 🟠 HIGH 7.5 | Resource exhaustion |
| netty-codec-http2 | 4.1.86 | CVE-2023-44487 | 🟠 HIGH 7.5 | HTTP/2 Rapid Reset |
| snakeyaml | 1.30 | CVE-2022-25857 | 🟠 HIGH 7.5 | YAML DoS |
| httpclient | 4.5.12 | CVE-2020-13956 | 🟡 MEDIUM 5.3 | URI handling flaw |

## How to run the POC

### Option 1 — Scanner UI (recommended)
Open `scanner-ui/index.html` in your browser and follow the on-screen steps.

### Option 2 — Command line (Windows CMD)
```cmd
osv-scanner.exe scan source --lockfile pom.xml --format json --output-file osv-report.json
```

## Project structure

```
osv-java-poc/
├── pom.xml                          ← vulnerable dependencies (OSV Scanner reads this)
├── src/main/java/com/osvpoc/App.java ← sample Java code using the libraries
├── scanner-ui/
│   └── index.html                   ← browser UI to scan and download CSV
└── README.md
```
