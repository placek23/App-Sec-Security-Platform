# AppSec Bounty Platform - User Guide

A comprehensive guide to using the AppSec Bounty Platform for security testing and bug bounty hunting.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Platform Architecture](#platform-architecture)
4. [Passive Reconnaissance](#passive-reconnaissance)
5. [Active Reconnaissance](#active-reconnaissance)
6. [Web Discovery](#web-discovery)
7. [Vulnerability Scanning](#vulnerability-scanning)
8. [Injection Testing](#injection-testing)
9. [Advanced Vulnerabilities](#advanced-vulnerabilities)
10. [API Testing](#api-testing)
11. [Authentication Testing](#authentication-testing)
12. [Manual Testing with Proxies](#manual-testing-with-proxies)
13. [Reporting](#reporting)
14. [Autonomous Hunting](#autonomous-hunting)
15. [Best Practices](#best-practices)
16. [Troubleshooting](#troubleshooting)

---

## Introduction

The AppSec Bounty Platform is an integrated security testing framework that wraps 30+ security tools into a unified Python interface. It's designed for:

- **Bug Bounty Hunters**: Automate reconnaissance and vulnerability discovery
- **Penetration Testers**: Streamline assessment workflows
- **Security Researchers**: Efficiently test applications at scale
- **Red Teams**: Conduct comprehensive security assessments

### Key Features

- **Unified Interface**: Consistent Python wrappers for all tools
- **Workflow Automation**: Pre-built pipelines for common tasks
- **Autonomous Agents**: AI-ready agents that can run complete assessments
- **Passive & Active Modes**: Safe pre-engagement recon and authorized testing
- **Comprehensive Reporting**: Multiple output formats with CVSS scoring
- **Database Storage**: Persist and analyze findings over time

---

## Getting Started

### Prerequisites

Before using the platform, ensure you have:

- Python 3.8 or higher
- Go 1.19 or higher
- Git
- Node.js (for some tools)

### Installation

1. **Clone and navigate to the platform:**
   ```bash
   cd C:\Users\grzeg\Development\appsec-bounty-platform
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run phase-specific setup scripts:**
   ```bash
   ./scripts/setup_phase1.sh   # Web Discovery tools
   ./scripts/setup_phase2.sh   # Proxy & Manual Testing
   ./scripts/setup_phase3.sh   # Injection Testing
   ./scripts/setup_phase4.sh   # API Testing
   ./scripts/setup_phase5.sh   # Auth Testing
   ./scripts/setup_phase6.sh   # Reporting
   ```

4. **Validate installation:**
   ```bash
   python validate.py
   python scripts/validate_phase1.py
   python scripts/validate_phase2.py
   # ... etc
   ```

### Quick Start

**Option 1: Full Autonomous Hunt**
```bash
python agents/bounty_hunter.py --target example.com --scope "*.example.com"
```

**Option 2: Step-by-Step Manual Workflow**
```bash
# 1. Passive recon (safe, no target contact)
python workflows/passive_recon.py -d example.com

# 2. Active recon (requires authorization)
python workflows/full_recon.py --target example.com

# 3. Vulnerability scanning
python workflows/vuln_scan.py --targets output/live_hosts.txt
```

---

## Platform Architecture

### Directory Structure

```
appsec-bounty-platform/
├── agents/                 # Autonomous hunting agents
│   ├── bounty_hunter.py   # Full pipeline agent
│   └── vuln_scanner.py    # Vulnerability scanning agent
├── workflows/             # Automated workflow pipelines
│   ├── passive_recon.py   # Passive reconnaissance
│   ├── full_recon.py      # Active reconnaissance
│   ├── web_discovery.py   # Directory/JS discovery
│   ├── vuln_scan.py       # Vulnerability scanning
│   ├── injection_test.py  # Injection testing
│   ├── advanced_vulns.py  # Advanced vulnerabilities
│   ├── api_testing.py     # API security testing
│   └── auth_testing.py    # Authentication testing
├── wrappers/              # Tool wrappers by category
│   ├── passive/           # Passive recon tools
│   ├── recon/             # Active recon tools
│   ├── discovery/         # Content discovery tools
│   ├── scanning/          # Vulnerability scanners
│   ├── injection/         # Injection testing tools
│   ├── advanced/          # Advanced vulnerability tools
│   ├── api/               # API testing tools
│   ├── auth/              # Authentication tools
│   └── proxy/             # Proxy integration
├── utils/                 # Utility modules
│   ├── base_wrapper.py    # Base classes for wrappers
│   ├── reporter.py        # Basic reporting
│   ├── advanced_reporter.py # CVSS-enabled reporting
│   ├── pdf_generator.py   # PDF report generation
│   ├── analytics.py       # Security analytics
│   ├── encoder.py         # Payload encoding
│   └── output_parser.py   # Parse tool outputs
├── database/              # Data persistence
│   ├── models.py          # SQLAlchemy models
│   └── manager.py         # Database operations
├── config/                # Configuration files
│   ├── tools.json         # Tool settings
│   ├── wordlists/         # Fuzzing wordlists
│   └── payloads/          # Attack payloads
├── output/                # Scan results (auto-created)
└── scripts/               # Setup & validation scripts
```

### Tool Categories

| Category | Purpose | Example Tools |
|----------|---------|---------------|
| Passive | No target contact | DNS enum, CT logs, WHOIS, Wayback |
| Recon | Subdomain/endpoint discovery | Subfinder, Amass, Httpx, Katana |
| Discovery | Content/parameter discovery | Gobuster, Dirsearch, Arjun, LinkFinder |
| Scanning | Vulnerability detection | Nuclei, WhatWeb, Wafw00f |
| Injection | Injection testing | SQLMap, Dalfox, Commix, Tplmap |
| Advanced | Complex vulnerabilities | SSRF, XXE, Smuggling, Race Conditions |
| API | API security | Kiterunner, GraphQL, WebSocket, OpenAPI |
| Auth | Authentication testing | JWT attacks, IDOR, Auth bypass |
| Proxy | Manual testing | ZAP, Request Builder, Session Manager |

---

## Passive Reconnaissance

Passive reconnaissance gathers information without directly contacting the target. This is safe for pre-engagement research and scoping.

### When to Use

- Before receiving authorization
- Scoping a bug bounty program
- Gathering background intelligence
- Building a target profile

### Available Tools

#### DNS Enumeration
Query public DNS servers for domain records:
```bash
python wrappers/passive/dns_enum.py -d example.com
python wrappers/passive/dns_enum.py -d example.com --record-types A,AAAA,MX,TXT,NS
```

#### Certificate Transparency
Find subdomains from CT logs (crt.sh, CertSpotter):
```bash
python wrappers/passive/cert_transparency.py -d example.com
python wrappers/passive/cert_transparency.py -d example.com --sources crtsh,certspotter
```

#### WHOIS Lookup
Get domain registration information:
```bash
python wrappers/passive/whois_lookup.py -d example.com
python wrappers/passive/whois_lookup.py -d example.com --historical
```

#### Wayback Machine
Retrieve historical URLs from the Internet Archive:
```bash
python wrappers/passive/wayback.py -d example.com
python wrappers/passive/wayback.py -d example.com --filter-ext js,php,aspx
```

#### OSINT Search
Generate and search using Google/GitHub dorks:
```bash
python wrappers/passive/osint_search.py -d example.com --google-dorks
python wrappers/passive/osint_search.py -d example.com --github-dorks
```

### Full Passive Workflow

Run all passive tools in one command:
```bash
python workflows/passive_recon.py -d example.com
```

Output is saved to `output/passive_example.com/`

---

## Active Reconnaissance

Active reconnaissance directly interacts with the target to discover subdomains, live hosts, and endpoints.

> **Warning**: Requires explicit authorization before use.

### Subdomain Discovery

#### Subfinder (Fast, Passive Sources)
```bash
python wrappers/recon/subfinder.py -d example.com -o subs.txt
python wrappers/recon/subfinder.py -d example.com --all -o subs.txt  # All sources
```

#### Amass (Comprehensive)
```bash
python wrappers/recon/amass.py -d example.com -o amass_subs.txt
python wrappers/recon/amass.py -d example.com -brute -o amass_subs.txt  # With brute force
```

### HTTP Probing

Determine which subdomains are live and responsive:
```bash
python wrappers/recon/httpx.py -l subdomains.txt -o live_hosts.txt
python wrappers/recon/httpx.py -l subs.txt -sc -title -o results.json --json
```

### Web Crawling

#### Katana (Active Crawling)
```bash
python wrappers/recon/katana.py -u https://example.com -o endpoints.txt
python wrappers/recon/katana.py -u https://example.com -d 3 -jc -o endpoints.txt  # Depth 3, JS crawling
```

#### GAU (Archive URLs)
```bash
python wrappers/recon/gau.py -d example.com -o archived_urls.txt
```

### Full Reconnaissance Workflow

Run the complete reconnaissance pipeline:
```bash
python workflows/full_recon.py --target example.com
```

This runs:
1. Subfinder + Amass (parallel subdomain discovery)
2. Httpx (HTTP probing)
3. Katana + GAU (endpoint discovery)

---

## Web Discovery

Web discovery focuses on finding hidden directories, files, JavaScript endpoints, and secrets.

### Directory Brute Forcing

#### Gobuster
```bash
python wrappers/discovery/gobuster.py -u https://example.com -w wordlists/common.txt
python wrappers/discovery/gobuster.py -u https://example.com -w wordlist.txt -x php,html -t 50
```

#### Dirsearch
```bash
python wrappers/discovery/dirsearch_wrapper.py -u https://example.com
python wrappers/discovery/dirsearch_wrapper.py -u https://example.com -e php,aspx,jsp -r
```

#### FFUF (Fuzzing)
```bash
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w wordlist.txt
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w wordlist.txt -mc 200,301,302
```

### JavaScript Analysis

#### LinkFinder (Endpoint Extraction)
```bash
python wrappers/discovery/linkfinder.py -u https://example.com/app.js
```

#### SecretFinder (Secret Detection)
```bash
python wrappers/discovery/secretfinder.py -u https://example.com/app.js
```

### Parameter Discovery

#### Arjun (Hidden Parameters)
```bash
python wrappers/discovery/arjun.py -u https://example.com/page
python wrappers/discovery/arjun.py -u https://example.com/page -m POST
```

#### ParamSpider (Archive Mining)
```bash
python wrappers/discovery/paramspider.py -d example.com
```

### Screenshots

#### GoWitness
```bash
python wrappers/discovery/gowitness.py -u https://example.com
python wrappers/discovery/gowitness.py -f urls.txt -o ./screenshots
```

### Full Web Discovery Workflow

```bash
python workflows/web_discovery.py -u https://example.com
```

---

## Vulnerability Scanning

### Nuclei (Template-Based Scanner)

Nuclei is the primary vulnerability scanner. Use profiles for targeted scanning:

```bash
# List available profiles
python wrappers/scanning/nuclei.py --list-profiles

# Quick scan (critical only)
python wrappers/scanning/nuclei.py -u https://example.com --profile quick

# Bug bounty profile (recommended)
python wrappers/scanning/nuclei.py -u https://example.com --profile bounty

# Full scan (all templates)
python wrappers/scanning/nuclei.py -u https://example.com --profile full

# Specific focus areas
python wrappers/scanning/nuclei.py -u https://example.com --profile injection  # SQLi/XSS/RCE
python wrappers/scanning/nuclei.py -u https://example.com --profile api        # API vulnerabilities
python wrappers/scanning/nuclei.py -u https://example.com --profile cve        # Known CVEs
```

#### CMS-Specific Profiles
```bash
python wrappers/scanning/nuclei.py -u https://example.com --profile wordpress
python wrappers/scanning/nuclei.py -u https://example.com --profile joomla
python wrappers/scanning/nuclei.py -u https://example.com --profile drupal
```

### WAF Detection

```bash
python wrappers/scanning/wafw00f.py -u https://example.com
```

### Technology Fingerprinting

```bash
python wrappers/scanning/whatweb.py -u https://example.com
python wrappers/scanning/whatweb.py -u https://example.com -a 3  # Aggressive
```

### Full Vulnerability Scan Workflow

```bash
python workflows/vuln_scan.py --targets urls.txt --severity high,critical
```

---

## Injection Testing

> **Warning**: Injection testing can modify data. Only use on authorized targets.

### SQL Injection (SQLMap)

```bash
# Basic test
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch

# Enumerate databases
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --dbs

# Thorough testing
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --level 3 --risk 2

# WAF bypass
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --tamper space2comment
```

### XSS (Dalfox)

```bash
# Basic scan
python wrappers/injection/dalfox.py -u "https://example.com/search?q=test"

# Blind XSS
python wrappers/injection/dalfox.py -u "https://example.com/search?q=test" --blind https://your-callback.com

# Batch mode
python wrappers/injection/dalfox.py -f urls.txt -o xss_results.json
```

### Command Injection (Commix)

```bash
python wrappers/injection/commix.py -u "https://example.com/ping?host=127.0.0.1" --batch
```

### Template Injection (Tplmap)

```bash
python wrappers/injection/tplmap.py -u "https://example.com/page?name=test"
python wrappers/injection/tplmap.py -u "https://example.com/page?name=test" -e jinja2
```

### NoSQL Injection

```bash
python wrappers/injection/nosql_injection.py -u "https://example.com/api/users" -p username
python wrappers/injection/nosql_injection.py -u "https://example.com/login" --test-auth
```

### LDAP Injection

```bash
python wrappers/injection/ldap_injection.py -u "https://example.com/search" -p query
```

### XPath Injection

```bash
python wrappers/injection/xpath_injection.py -u "https://example.com/xml" -p id
```

### Advanced XSS (DOM & CSP Bypass)

```bash
python wrappers/injection/advanced_xss.py -u "https://example.com/search" -p q --test-dom
python wrappers/injection/advanced_xss.py -u "https://example.com/app" -p data --test-csp
```

### Full Injection Testing Workflow

```bash
python workflows/injection_test.py --urls urls_with_params.txt
python workflows/injection_test.py --urls urls_with_params.txt --sqli-only  # SQL injection only
```

---

## Advanced Vulnerabilities

### SSRF (Server-Side Request Forgery)

```bash
# Basic SSRF test
python wrappers/advanced/ssrf_tester.py -u "https://example.com/fetch" -p url

# Cloud metadata test
python wrappers/advanced/ssrf_tester.py -u "https://example.com/fetch" -p url --test-type cloud

# With callback
python wrappers/advanced/ssrf_tester.py -u "https://example.com/fetch" -p url --callback http://your-callback.com
```

### XXE (XML External Entity)

```bash
python wrappers/advanced/xxe_injector.py -u "https://example.com/api/xml"
python wrappers/advanced/xxe_injector.py -u "https://example.com/api/xml" --callback http://your-callback.com
```

### HTTP Request Smuggling

```bash
python wrappers/advanced/http_smuggler.py -u "https://example.com/"
python wrappers/advanced/http_smuggler.py -u "https://example.com/" --test-type clte
python wrappers/advanced/http_smuggler.py -u "https://example.com/" --test-type tecl
```

### Race Conditions

```bash
# Basic race test
python wrappers/advanced/race_condition.py -u "https://example.com/redeem" -n 20

# Limit overrun test
python wrappers/advanced/race_condition.py -u "https://example.com/coupon" --test-type limit --expected-limit 1
```

### CORS Misconfiguration

```bash
python wrappers/advanced/cors_tester.py -u "https://example.com/api/data"
python wrappers/advanced/cors_tester.py -u "https://api.example.com/users" --origins "https://evil.com"
```

### File Upload Bypass

```bash
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload"
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload" --test-type all
```

### Full Advanced Vulnerabilities Workflow

```bash
python workflows/advanced_vulns.py -t "https://example.com"
python workflows/advanced_vulns.py -t "https://example.com" --callback http://your-callback.com
```

---

## API Testing

### API Endpoint Discovery

#### Kiterunner
```bash
python wrappers/api/kiterunner.py -u https://api.example.com
python wrappers/api/kiterunner.py -u https://api.example.com -A routes-large.kite
```

### OpenAPI/Swagger Analysis

```bash
python wrappers/api/openapi_analyzer.py -u https://api.example.com
python wrappers/api/openapi_analyzer.py -u https://api.example.com --spec swagger.json --test
```

### GraphQL Testing

```bash
# Introspection test
python wrappers/api/graphql_tester.py -u https://example.com/graphql --tests introspection

# Multiple tests
python wrappers/api/graphql_tester.py -u https://example.com/graphql --tests introspection,batch,depth

# DoS test
python wrappers/api/graphql_tester.py -u https://example.com/graphql --tests dos --depth 15
```

### WebSocket Testing

```bash
python wrappers/api/websocket_tester.py -u wss://example.com/ws
python wrappers/api/websocket_tester.py -u wss://example.com/ws --tests origin,auth,injection
```

### JWT Testing

```bash
# Decode token
python wrappers/api/jwt_tester.py -t "eyJhbG..." --decode

# Test vulnerabilities
python wrappers/api/jwt_tester.py -t "eyJhbG..." --url https://api.example.com/me

# Crack weak secret
python wrappers/api/jwt_tester.py -t "eyJhbG..." --url https://api.example.com/me --wordlist jwt_secrets.txt
```

### Full API Testing Workflow

```bash
python workflows/api_testing.py -t https://api.example.com
python workflows/api_testing.py -t https://api.example.com --test discovery,openapi,graphql
```

---

## Authentication Testing

### Authentication Bypass

```bash
# SQL injection bypass
python wrappers/auth/auth_bypass.py -u https://example.com/login --test-types sql

# Default credentials
python wrappers/auth/auth_bypass.py -u https://example.com/login --test-types default

# All bypass types
python wrappers/auth/auth_bypass.py -u https://example.com/login --test-types sql,default,header,path
```

### IDOR (Insecure Direct Object Reference)

```bash
# Numeric ID enumeration
python wrappers/auth/idor_tester.py -u "https://api.example.com/users/{id}" -p id

# With authentication
python wrappers/auth/idor_tester.py -u "https://api.example.com/profile" -p user_id -t "Bearer token" --count 50

# UUID enumeration
python wrappers/auth/idor_tester.py -u "https://api.example.com/doc/{uuid}" --test-types uuid
```

### JWT Attacks

```bash
# None algorithm attack
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --test-types none

# Weak secret attack
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --test-types weak

# Full attack suite
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --test-types none,weak,kid
```

### Privilege Escalation

```bash
python wrappers/auth/privilege_escalation.py -u https://example.com
python wrappers/auth/privilege_escalation.py -u https://example.com -t "Bearer low_priv_token" --test-types endpoint,role,param
```

### Password Brute Forcing (Hydra)

```bash
# SSH
python wrappers/auth/hydra_wrapper.py -t 192.168.1.1 -s ssh -l admin -P passwords.txt

# HTTP POST form
python wrappers/auth/hydra_wrapper.py -t example.com -s http-post-form \
    --form-path "/login" \
    --form-data "user=^USER^&pass=^PASS^" \
    --fail-string "Invalid" \
    -L users.txt -P passwords.txt
```

### Full Authentication Testing Workflow

```bash
python workflows/auth_testing.py -t https://example.com --login-url https://example.com/login
python workflows/auth_testing.py -t https://example.com --login-url /login --api-url "/api/users/{id}" --jwt-token "eyJ..."
```

---

## Manual Testing with Proxies

### ZAP Integration

First, start ZAP in daemon mode:
```bash
zap.sh -daemon -port 8080
```

Then use the integration:
```bash
# Full scan (spider + active scan)
python wrappers/proxy/zap_integration.py --target https://example.com --full

# Spider only
python wrappers/proxy/zap_integration.py --target https://example.com --spider

# Export reports
python wrappers/proxy/zap_integration.py --target https://example.com --full --report html
```

### Request Builder

Build and send custom HTTP requests:
```bash
# Basic request
python wrappers/proxy/request_builder.py --url https://example.com/api

# POST with data
python wrappers/proxy/request_builder.py --url https://example.com/api \
    --method POST \
    --data '{"test": 1}' \
    -H "Content-Type: application/json"

# Fuzz a parameter
python wrappers/proxy/request_builder.py \
    --url "https://example.com/search?q=test" \
    --fuzz-param q \
    --wordlist wordlists/xss.txt
```

### Session Manager

Manage authentication sessions:
```bash
# Create session
python wrappers/proxy/session_manager.py --action create --name admin_session

# Add token
python wrappers/proxy/session_manager.py --action add-token \
    --name admin_session \
    --token-name access_token \
    --token-value "eyJ..." \
    --token-type bearer

# Save/load sessions
python wrappers/proxy/session_manager.py --action save --file sessions.json
python wrappers/proxy/session_manager.py --action load --file sessions.json
```

### Payload Encoder

Encode payloads for bypass testing:
```bash
# URL encode
python utils/encoder.py "' OR 1=1--" --encode url

# Chain encodings
python utils/encoder.py "' OR 1=1--" --encode url --encode base64

# Generate bypass variants
python utils/encoder.py --xss "<script>alert(1)</script>"
python utils/encoder.py --sql "' OR 1=1--"
```

---

## Reporting

### Basic Reporter

```python
from utils.reporter import Reporter

reporter = Reporter()
reporter.add_finding({
    'title': 'SQL Injection',
    'severity': 'critical',
    'url': 'https://example.com/login',
    'description': 'SQL injection in login form'
})
reporter.generate_html_report('report.html')
```

### Advanced Reporter (CVSS Scoring)

```python
from utils.advanced_reporter import AdvancedReporter

reporter = AdvancedReporter(output_dir='./output/reports')
reporter.set_metadata(
    title='Security Assessment',
    target='example.com',
    tester='Security Team'
)

# Findings auto-enriched with CVSS scores
reporter.add_finding(
    title='SQL Injection',
    severity='critical',
    finding_type='sqli',  # Auto-enriched with CWE-89, CVSS 9.8
    tool='sqlmap',
    url='https://example.com/login'
)

# Export all formats
paths = reporter.export_all('assessment_report')
```

### PDF Reports

```bash
python utils/pdf_generator.py  # Demo mode

# Or programmatically:
from utils.pdf_generator import PDFReportGenerator
generator = PDFReportGenerator()
path = generator.generate(report_data)
```

### Database Storage

Store and query scan results:
```python
from database.manager import DatabaseManager

db = DatabaseManager()

# Create target and scan
target = db.create_target('Example Corp', 'example.com')
scan = db.create_scan(target['id'], 'vulnerability_scan')

# Add findings
db.add_finding(scan['id'], 'SQL Injection', 'critical', finding_type='sqli')

# Get statistics
stats = db.get_summary_stats(target_id=target['id'])
```

### Analytics

```python
from utils.analytics import SecurityAnalytics

analytics = SecurityAnalytics()
report_data = analytics.generate_report_data(scans, findings)

print(f"Risk Score: {report_data['security_score']['score']}")
print(f"Grade: {report_data['security_score']['grade']}")
```

### Multi-Target Aggregation

```python
from utils.report_aggregator import ReportAggregator

aggregator = ReportAggregator()
aggregator.add_scan_results('target1.com', scan={}, findings=[...])
aggregator.add_scan_results('target2.com', scan={}, findings=[...])
paths = aggregator.export_all()
```

---

## Autonomous Hunting

### Bounty Hunter Agent

The bounty hunter agent runs the complete pipeline automatically:

```bash
# Basic hunt
python agents/bounty_hunter.py --target example.com

# With scope filtering
python agents/bounty_hunter.py --target example.com --scope "*.example.com"

# Exclude out-of-scope
python agents/bounty_hunter.py --target example.com \
    --scope "*.example.com" \
    --out-of-scope "admin.example.com,staging.example.com"

# Filter severity and set time limit
python agents/bounty_hunter.py --target example.com \
    --scope "*.example.com" \
    --severity medium \
    --max-time 7200
```

### Vulnerability Scanner Agent

Focused vulnerability scanning:
```bash
# Quick scan
python agents/vuln_scanner.py -t https://example.com --type quick

# Full scan
python agents/vuln_scanner.py -t https://example.com --type full

# Injection-focused
python agents/vuln_scanner.py -t https://example.com --type injection

# From file
python agents/vuln_scanner.py -f urls.txt --type full --severity high,critical
```

---

## Best Practices

### Before Testing

1. **Get Authorization**: Always have written permission before testing
2. **Define Scope**: Know what's in-scope and out-of-scope
3. **Start Passive**: Run passive recon first to understand the target
4. **Check Rate Limits**: Respect program rate limits to avoid bans

### During Testing

1. **Use Profiles**: Start with `quick` or `stealth` profiles, escalate as needed
2. **Monitor Output**: Watch for errors and adjust rate limits
3. **Document Everything**: Keep notes on findings and methodology
4. **Be Careful with Injection**: Injection tests can modify data

### After Testing

1. **Generate Reports**: Create professional reports with CVSS scores
2. **Store Results**: Use the database for historical tracking
3. **Clean Up**: Remove any test data you created
4. **Report Responsibly**: Follow responsible disclosure guidelines

### Rate Limiting

Most tools support rate limiting:
```bash
# Nuclei
python wrappers/scanning/nuclei.py -u https://example.com --profile bounty -rl 30

# FFUF
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w wordlist.txt -rate 50

# Hydra
python wrappers/auth/hydra_wrapper.py -t example.com -s ssh -l admin -P passwords.txt --rate 10
```

---

## Troubleshooting

### Tool Not Found

If a tool wrapper fails with "command not found":
```bash
# Check if tool is installed
which subfinder
which nuclei

# Reinstall if needed
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify Go bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

### Permission Errors

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Run validation
python validate.py
```

### Rate Limiting / Blocking

If you're getting blocked:
1. Reduce request rate with `--rate` or `-rl` flags
2. Use the `stealth` Nuclei profile
3. Add delays between tools in workflows
4. Use rotating proxies if allowed

### Database Issues

```bash
# Initialize/reset database
python -c "from database.models import init_db; init_db()"

# Check database location
ls -la output/appsec_bounty.db
```

### ZAP Connection Issues

```bash
# Ensure ZAP is running
zap.sh -daemon -port 8080 -config api.key=your_api_key

# Test connection
python -c "from zapv2 import ZAPv2; zap = ZAPv2(); print(zap.core.version)"
```

### Output Not Found

Default output goes to `./output/`. Check:
```bash
ls -la output/
ls -la output/recon/
ls -la output/scanning/
```

---

## Getting Help

- **Command Reference**: See `COMMANDS.md` for all available commands
- **Implementation Details**: See `IMPLEMENTATION_GUIDE.md` for technical details
- **Claude Code Integration**: See `CLAUDE.md` for AI assistant guidance

---

## Legal Notice

This platform is intended for authorized security testing only. Always:

- Obtain written permission before testing
- Respect scope limitations
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

Passive reconnaissance tools query public databases only, but active scanning requires explicit authorization.
