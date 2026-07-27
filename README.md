# TrinTech Digital Defense — Full Network Audit Suite

> **DEFEND. DETECT. DOMINATE.**

All-in-one network scanning, reconnaissance, and professional PDF reporting tool for TrinTech Digital Defense engagements.

## What It Does

One command that maps an entire network, discovers vulnerabilities, and produces a client-ready PDF report — the way Jason handles every engagement.

### The Workflow

```
$ trintech-audit start "Client Name" target.com --service smallbiz
$ trintech-audit run ENG-260727-ABC123 --modules recon,web,osint
$ trintech-audit report ENG-260727-ABC123
# -> ENG-260727-ABC123_Client_Name_Audit_Report.pdf (4-page professional PDF)
```

## Installation

```bash
pip install reportlab dnspython phonenumbers
```

No external binaries required (uses Python socket scanning, `dig`, `whois` CLI).

## Quick Start

### 1. Create an engagement

```bash
python main.py start "Acme Corp" example.com --service smallbiz --devices 10
```

Output: `ENG-260727-118D0C`

### 2. Run scan modules

| Module | What it does |
|--------|-------------|
| `recon` | Port scan, service banners, DNS enumeration, subdomain discovery, SSL check, WHOIS |
| `web` | Web vulnerability scan — security headers, tech fingerprinting, info disclosure, sensitive path detection |
| `osint` | Public intelligence — domain info, email footprint, WHOIS, social media presence |
| `vuln` | Vulnerability assessment across all discovered services |
| `all` | Runs every module |

```bash
python main.py run ENG-260727-118D0C --modules recon,web,osint
```

### 3. Generate the PDF report

```bash
python main.py report ENG-260727-118D0C
```

Output: A 4-page PDF with:
- **Cover page** — Client info, security score (0-100), grade (A-F), NDA notice
- **Executive Summary** — Score breakdown, findings by severity, overall posture
- **Detailed Findings** — Each finding with "What it means" + "What to do" in plain English
- **Network Discovery** — Open ports, DNS records, SSL grade, subdomains
- **Remediation Roadmap** — Prioritized by urgency (Immediate / This Week / This Month / Ongoing)
- **Conclusion** — Contact info, next steps

### 4. List engagements

```bash
python main.py list
```

## Architecture

```
trintech-audit/
├── main.py              # CLI entry point, engagement management
├── pdf_report.py        # Professional PDF report generator (reportlab)
├── recon/
│   ├── recon_engine.py  # Port scanning, banner grabbing, DNS, SSL, WHOIS
│   ├── web_scan.py      # Web vulnerability scanning (headers, tech, paths)
│   ├── osint_scan.py    # Public intelligence gathering
│   └── vuln_scan.py     # Vulnerability detection across all services
├── reports/             # Scan data (JSON) and generated PDFs
├── data/                # Engagement database (JSON)
└── __init__.py
```

## Dependencies

- **reportlab** — PDF generation
- **dnspython** — DNS enumeration
- **phonenumbers** — Phone metadata parsing
- **nmap** — Port scanning (system package, `apt install nmap`)
- **whois** — WHOIS lookup (system package, `apt install whois`)
- **dig/host** — DNS queries (system package, `apt install dnsutils`)

## How It Differs From Other Tools

| | TrinTech Audit | Nmap | Nikto | Burp |
|---|---|---|---|---|
| Port scanning | ✅ | ✅ | ❌ | ❌ |
| Web vulns | ✅ | ❌ | ✅ | ✅ |
| OSINT | ✅ | ❌ | ❌ | ❌ |
| SSL/TLS check | ✅ | ✅ | ❌ | ❌ |
| DNS enumeration | ✅ | ❌ | ❌ | ❌ |
| **PDF report** | **✅** | ❌ | ❌ | ❌ |
| **Client-ready** | **✅** | ❌ | ❌ | ❌ |

## Service Pricing Alignment

| Service | Default Scope |
|---------|-------------|
| Micro ($1,000) | 1-5 devices, basic recon + web scan |
| Small Business ($2,200) | 5-15 devices, full recon + web + OSINT |
| Pentest (Custom) | Full suite + exploitation addons |

## Notes

- All scans are authorized testing only
- Reports include NDA confidentiality notice
- Score calculation: 100 - (critical×25 + high×12 + medium×5 + low×2), min 0
- Scan data persists as JSON in `reports/` directory
- Engagement database persists in `data/engagements.json`
