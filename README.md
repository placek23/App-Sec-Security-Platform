# 🎯 AppSec Bounty Platform

A streamlined application security testing and bug bounty hunting platform designed for Claude Code integration. This platform provides 20 essential security tools organized into a logical workflow for discovering vulnerabilities in web applications.

## 🚀 Features

- **20 Curated Tools** - Hand-picked for app pentesting and bug bounty
- **Automated Workflows** - Pre-built pipelines for common tasks
- **Autonomous Agent** - Full bug bounty hunting automation
- **Claude Code Integration** - Designed as a skill for AI-assisted security testing
- **Beautiful Reports** - HTML, JSON, and Markdown output formats

## 📦 Installation

### 1. Clone/Copy the Platform
```bash
# Copy to your preferred location
cp -r appsec-bounty-platform ~/tools/
cd ~/tools/appsec-bounty-platform
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Security Tools

#### Go-based tools (recommended to install via `go install`):
```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# HTTP utilities
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# Fuzzing
go install -v github.com/ffuf/ffuf/v2@latest

# Scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# XSS
go install -v github.com/hahwul/dalfox/v2@latest

# Subdomain takeover
go install -v github.com/haccer/subjack@latest
```

#### Rust-based tools:
```bash
cargo install feroxbuster
```

#### Python-based tools:
```bash
pip install arjun wafw00f sqlmap commix
```

## 🔧 Tool Categories

### Phase 1: Reconnaissance
| Tool | Purpose | Priority |
|------|---------|----------|
| subfinder | Passive subdomain discovery | ⭐⭐⭐ |
| amass | Advanced enumeration + OSINT | ⭐⭐⭐ |
| httpx | HTTP probing + tech detection | ⭐⭐⭐ |
| katana | JS-aware web crawling | ⭐⭐⭐ |
| gau | URL harvesting from archives | ⭐⭐⭐ |

### Phase 2: Content Discovery
| Tool | Purpose | Priority |
|------|---------|----------|
| ffuf | Universal fuzzer | ⭐⭐⭐ |
| feroxbuster | Recursive discovery | ⭐⭐⭐ |
| arjun | Parameter discovery | ⭐⭐⭐ |
| paramspider | Archive parameter mining | ⭐⭐⭐ |

### Phase 3: Vulnerability Scanning
| Tool | Purpose | Priority |
|------|---------|----------|
| nuclei | Template-based scanner (4000+ templates) | ⭐⭐⭐ |
| wafw00f | WAF detection | ⭐⭐⭐ |
| whatweb | Technology fingerprinting | ⭐⭐ |

### Phase 4: Injection Testing
| Tool | Purpose | Priority |
|------|---------|----------|
| sqlmap | SQL injection | ⭐⭐⭐ |
| dalfox | XSS with DOM analysis | ⭐⭐⭐ |
| commix | Command injection | ⭐⭐⭐ |
| tplmap | SSTI exploitation | ⭐⭐⭐ |

### Phase 5: Auth & API Testing
| Tool | Purpose | Priority |
|------|---------|----------|
| jwt_tool | JWT attacks | ⭐⭐⭐ |
| subjack | Subdomain takeover | ⭐⭐⭐ |
| graphql_voyager | GraphQL testing | ⭐⭐⭐ |
| testssl | SSL/TLS testing | ⭐⭐ |

## 📚 Usage

### Quick Start - Autonomous Bug Bounty Hunt
```bash
# Full automated hunt
python agents/bounty_hunter.py --target example.com

# With scope restrictions
python agents/bounty_hunter.py --target example.com \
    --scope "*.example.com" \
    --out-of-scope "admin.example.com"

# Quick scan (high severity only)
python agents/bounty_hunter.py --target example.com \
    --severity high \
    --max-time 1800
```

### Individual Workflows

#### Full Reconnaissance
```bash
python workflows/full_recon.py --target example.com
```

#### Vulnerability Scanning
```bash
python workflows/vuln_scan.py --target example.com
python workflows/vuln_scan.py --urls live_hosts.txt --severity high,critical
```

#### Injection Testing
```bash
python workflows/injection_test.py --target "https://example.com/page?id=1"
python workflows/injection_test.py --urls urls_with_params.txt
```

### Individual Tool Wrappers
```bash
# Subdomain discovery
python wrappers/recon/subfinder.py -d example.com -o subdomains.txt

# HTTP probing
python wrappers/recon/httpx.py -l subdomains.txt -o live.json

# Nuclei scanning
python wrappers/scanning/nuclei.py -l live.txt -severity high,critical

# SQL injection testing
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch
```

## 📁 Project Structure

```
appsec-bounty-platform/
├── SKILL.md                 # Claude Code skill documentation
├── README.md                # This file
├── requirements.txt         # Python dependencies
├── config/
│   └── tools.json          # Tool configuration
├── utils/
│   ├── base_wrapper.py     # Base class for tool wrappers
│   ├── output_parser.py    # Standardized output parsing
│   ├── reporter.py         # Report generation
│   └── rate_limiter.py     # Rate limiting utilities
├── wrappers/
│   ├── recon/              # Reconnaissance tools
│   ├── discovery/          # Content discovery tools
│   ├── scanning/           # Vulnerability scanners
│   ├── injection/          # Injection testing tools
│   ├── auth/               # Authentication testing
│   └── api/                # API testing tools
├── workflows/
│   ├── full_recon.py       # Complete recon pipeline
│   ├── vuln_scan.py        # Vulnerability scanning workflow
│   └── injection_test.py   # Injection testing workflow
├── agents/
│   └── bounty_hunter.py    # Autonomous bug bounty agent
├── templates/              # Report templates
└── output/                 # Scan results
```

## 🔄 Workflow Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    TARGET ACQUISITION                            │
│                         example.com                              │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 1: RECONNAISSANCE                             │
│  subfinder → amass → httpx → katana → gau                       │
│  Output: subdomains.txt, live_hosts.txt, urls.txt               │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 2: CONTENT DISCOVERY                          │
│  ffuf → feroxbuster → arjun → paramspider                       │
│  Output: directories.txt, endpoints.txt, params.txt             │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 3: VULNERABILITY SCANNING                     │
│  wafw00f (detect WAF) → nuclei (mass scan) → whatweb           │
│  Output: vulns.json, technologies.txt, waf_info.txt            │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 4: INJECTION TESTING                          │
│  sqlmap → dalfox → commix → tplmap                              │
│  Output: sqli_results.txt, xss_results.txt, rce_results.txt    │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              PHASE 5: AUTH & API TESTING                         │
│  jwt_tool → subjack → graphql_voyager → testssl                 │
│  Output: jwt_vulns.txt, takeovers.txt, api_vulns.txt           │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    REPORT GENERATION                             │
│  HTML + JSON + Markdown reports                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 🤖 Claude Code Integration

This platform is designed to work as a Claude Code skill. To integrate:

1. Copy the `appsec-bounty-platform` folder to your Claude Code skills directory
2. Reference the `SKILL.md` file in your Claude Code configuration
3. Use natural language to invoke tools:
   - "Run reconnaissance on example.com"
   - "Scan for vulnerabilities in these URLs"
   - "Test this endpoint for SQL injection"

## ⚠️ Legal Notice

**IMPORTANT**: This platform is intended for authorized security testing only.

- Only use on systems you own or have explicit written permission to test
- Unauthorized security testing is illegal and unethical
- Always follow responsible disclosure practices
- Respect rate limits and scope boundaries

## 📄 License

This project is for educational and authorized security testing purposes only.

## 🙏 Credits

This platform integrates and wraps the following open-source security tools:
- ProjectDiscovery (subfinder, httpx, nuclei, katana)
- OWASP (amass)
- sqlmapproject (sqlmap)
- hahwul (dalfox)
- And many more amazing security tools!
