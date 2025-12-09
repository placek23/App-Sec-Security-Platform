# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AppSec Bounty Platform is a comprehensive security testing and bug bounty hunting platform designed for Claude Code integration. It wraps 30+ security tools into Python wrappers with standardized interfaces, organized into a multi-phase workflow pipeline with both **passive** and **active** scanning capabilities.

## Common Commands

### Autonomous Bug Bounty Hunt
```bash
python agents/bounty_hunter.py --target example.com
python agents/bounty_hunter.py --target example.com --scope "*.example.com" --severity high --max-time 1800
```

### Passive Reconnaissance (No Direct Target Interaction)
```bash
# Full passive recon - safe for pre-engagement research
python workflows/passive_recon.py -d example.com

# Individual passive tools
python wrappers/passive/dns_enum.py -d example.com
python wrappers/passive/cert_transparency.py -d example.com
python wrappers/passive/whois_lookup.py -d example.com
python wrappers/passive/wayback.py -d example.com
python wrappers/passive/osint_search.py -d example.com --google-dorks
```

### Active Web Discovery (Phase 1)
```bash
# Combined web discovery workflow
python workflows/web_discovery.py -u https://example.com

# Individual discovery tools
python wrappers/discovery/gobuster.py -u https://example.com -w wordlists/common.txt
python wrappers/discovery/dirsearch_wrapper.py -u https://example.com
python wrappers/discovery/linkfinder.py -u https://example.com/app.js
python wrappers/discovery/secretfinder.py -u https://example.com/app.js
python wrappers/discovery/gowitness.py -u https://example.com
```

### Proxy & Manual Testing (Phase 2)
```bash
# ZAP Integration (requires ZAP running)
python wrappers/proxy/zap_integration.py --target https://example.com --full
python wrappers/proxy/zap_integration.py --target https://example.com --spider --scan

# Request Builder for manual testing
python wrappers/proxy/request_builder.py --url https://example.com/api --method POST --data '{"test": 1}'
python wrappers/proxy/request_builder.py --url https://example.com/search?q=test --fuzz-param q --wordlist wordlists/xss.txt

# Session Manager for authentication
python wrappers/proxy/session_manager.py --action create --name admin_session
python wrappers/proxy/session_manager.py --action list

# Payload Encoder for bypass testing
python utils/encoder.py "<script>alert(1)</script>"
python utils/encoder.py "' OR 1=1--" --encode url --encode base64
python utils/encoder.py --xss "<script>alert(1)</script>"
```

### Advanced Injection Testing (Phase 3)
```bash
# NoSQL Injection Testing
python wrappers/injection/nosql_injection.py -u "https://example.com/api/users" -p username
python wrappers/injection/nosql_injection.py -u "https://example.com/login" --test-auth

# LDAP Injection Testing
python wrappers/injection/ldap_injection.py -u "https://example.com/search" -p query
python wrappers/injection/ldap_injection.py -u "https://example.com/auth" -p user --test-blind

# XPath Injection Testing
python wrappers/injection/xpath_injection.py -u "https://example.com/xml" -p id
python wrappers/injection/xpath_injection.py -u "https://example.com/search" -p q --test-blind

# Advanced XSS Testing (DOM, CSP Bypass)
python wrappers/injection/advanced_xss.py -u "https://example.com/search" -p q
python wrappers/injection/advanced_xss.py -u "https://example.com/page" -p input --test-dom
```

### Advanced Web Vulnerabilities (Phase 3.5)
```bash
# Full advanced vulnerability scan
python workflows/advanced_vulns.py -t "https://example.com"
python workflows/advanced_vulns.py -t "https://example.com/api" --callback http://your-callback.com

# SSRF Testing
python wrappers/advanced/ssrf_tester.py -u "https://example.com/fetch" -p url
python wrappers/advanced/ssrf_tester.py -u "https://example.com/proxy" -p target --test-type cloud

# XXE Injection Testing
python wrappers/advanced/xxe_injector.py -u "https://example.com/api/xml"
python wrappers/advanced/xxe_injector.py -u "https://example.com/upload" --callback http://your-callback.com

# HTTP Request Smuggling
python wrappers/advanced/http_smuggler.py -u "https://example.com/"
python wrappers/advanced/http_smuggler.py -u "https://example.com/" --test-type tete

# Race Condition Testing
python wrappers/advanced/race_condition.py -u "https://example.com/redeem" -n 20
python wrappers/advanced/race_condition.py -u "https://example.com/vote" --test-type limit

# CORS Misconfiguration Testing
python wrappers/advanced/cors_tester.py -u "https://example.com/api/data"
python wrappers/advanced/cors_tester.py -u "https://api.example.com/users" --origins "https://evil.com"

# File Upload Bypass Testing
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload"
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload" --param uploadFile --test-type all
```

### Vulnerability Scanning & Testing
```bash
python workflows/full_recon.py --target example.com
python workflows/vuln_scan.py --target example.com --severity high,critical
python workflows/injection_test.py --target "https://example.com/page?id=1"
```

### Individual Tool Wrappers
```bash
python wrappers/recon/subfinder.py -d example.com -o subdomains.txt
python wrappers/scanning/nuclei.py -l urls.txt -severity high,critical
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch
```

### Install Dependencies
```bash
pip install -r requirements.txt
./scripts/setup_phase1.sh  # Install Phase 1 tools
./scripts/setup_phase2.sh  # Install Phase 2 tools (ZAP, mitmproxy, etc.)
./scripts/setup_phase3.sh  # Install Phase 3 tools (Advanced injection testing)
```

### Validate Installation
```bash
python scripts/validate_phase1.py
python scripts/validate_phase2.py
python scripts/validate_phase3.py
python scripts/test_phase1.py
```

## Architecture

### Tool Wrapper Hierarchy

All tool wrappers inherit from `BaseToolWrapper` in `utils/base_wrapper.py`. Category-specific base classes exist:

**Passive Tools** (No direct target interaction):
- `DNSEnumerator` - DNS records via public DNS servers
- `CertTransparency` - Certificate Transparency log analysis
- `WhoisLookup` - WHOIS database queries
- `WaybackMachine` - Internet Archive historical data
- `OSINTSearch` - Google/GitHub dorks, social media search

**Active Tools** (Direct target interaction):
- `ReconTool` - reconnaissance tools (subfinder, amass, httpx, katana, gau)
- `DiscoveryTool` - content discovery (gobuster, dirsearch, ffuf, feroxbuster, arjun, paramspider)
- `ScanningTool` - vulnerability scanning (nuclei, wafw00f, whatweb)
- `InjectionTool` - injection testing (sqlmap, dalfox, commix, tplmap)
- `AuthTool` - authentication testing (jwt_tool, subjack)
- `APITool` - API testing (graphql_voyager, testssl)
- `ProxyTool` - proxy integration tools (ZAP, mitmproxy)

**Web Discovery Tools** (Phase 1):
- `GobusterWrapper` - Directory/file brute forcing
- `DirsearchWrapper` - Web path discovery
- `LinkFinderWrapper` - JavaScript endpoint extraction
- `SecretFinderWrapper` - Secret detection in JS files
- `GoWitnessWrapper` - Screenshot capture

**Proxy & Manual Testing Tools** (Phase 2):
- `ZAPIntegration` - OWASP ZAP spider, scan, and report generation
- `RequestBuilder` - HTTP request building, fuzzing, and history tracking
- `SessionManager` - Authentication session and token management
- `PayloadEncoder` - Encoding utilities for bypass testing

Each wrapper must implement:
- `tool_name` property - returns tool binary name
- `_build_target_args()` - builds CLI arguments for the tool

### Pipeline Flow

```
                    ┌─────────────────────────────────────────┐
                    │           PASSIVE RECON                 │
                    │  (Safe - No Target Interaction)         │
                    │                                         │
                    │  DNS Enum → CT Logs → WHOIS →          │
                    │  Wayback → OSINT Dorks                  │
                    └────────────────┬────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                         ACTIVE SCANNING PIPELINE                            │
│                    (Requires Authorization)                                 │
│                                                                             │
│  Target → Recon → Discovery → Scanning → Injection → Auth/API → Report    │
└────────────────────────────────────────────────────────────────────────────┘
```

**Passive Phase** (Pre-engagement):
1. DNS enumeration via public DNS servers
2. Certificate Transparency log analysis (crt.sh, CertSpotter)
3. WHOIS registration data
4. Wayback Machine historical URLs
5. OSINT search and dork generation

**Active Phases** (Requires authorization):
1. **Reconnaissance**: subfinder + amass (subdomains) → httpx (probing) → katana + gau (crawling)
2. **Web Discovery**: gobuster/dirsearch (dirs) → linkfinder/secretfinder (JS analysis) → gowitness (screenshots)
3. **Vulnerability Scanning**: wafw00f (WAF detection) → nuclei → whatweb
4. **Injection Testing**: sqlmap, dalfox, commix, tplmap
5. **Auth/API Testing**: jwt_tool, subjack, testssl

### Key Classes

**Workflows & Agents**:
- `PassiveReconWorkflow` (`workflows/passive_recon.py`): Combines all passive OSINT tools for comprehensive reconnaissance without target interaction
- `WebDiscoveryWorkflow` (`workflows/web_discovery.py`): Runs directory discovery, JS analysis, and screenshot capture
- `BountyHunterAgent` (`agents/bounty_hunter.py`): Orchestrates the complete multi-phase pipeline with scope filtering, timeout management, and report generation
- `FullReconWorkflow` (`workflows/full_recon.py`): Runs parallel subdomain discovery, HTTP probing, crawling, and URL harvesting
- `Reporter` (`utils/reporter.py`): Generates HTML/JSON/Markdown reports with severity breakdowns

**Phase 2 - Manual Testing Support**:
- `ZAPIntegration` (`wrappers/proxy/zap_integration.py`): OWASP ZAP API integration for spidering, active scanning, and report generation
- `RequestBuilder` (`wrappers/proxy/request_builder.py`): HTTP request builder with fuzzing, history tracking, and HAR export
- `SessionManager` (`wrappers/proxy/session_manager.py`): Session/token management for JWT, API keys, Basic auth with persistence
- `PayloadEncoder` (`utils/encoder.py`): Encoding utilities (URL, Base64, HTML, Unicode, Hex) with XSS/SQL bypass variants

### Configuration

`config/tools.json` contains:
- Tool binary paths and default arguments
- Rate limiting settings (`requests_per_second`, `delay_between_tools`)
- Timeout values per tool
- Workflow definitions (which tools run in parallel vs sequential)

`config/wordlists/` contains:
- `common.txt` - Common directory/file names
- `medium.txt` - Extended wordlist for thorough discovery

### Output Structure

All output goes to `./output/` by default:
- `output/passive_*/` - Passive recon results (subdomains, URLs, parameters, dorks)
- `output/discovery/` - Directory brute force, JS endpoints, secrets, screenshots
- `output/recon/` - Subdomains, live hosts, endpoints
- `output/scanning/` - Nuclei findings, WAF info
- `output/injection/` - SQLi, XSS, command injection results
- `output/bounty_*/` - Full hunt results with HTML report
- `output/zap/` - ZAP scan reports (HTML, JSON, XML)
- `output/sessions/` - Session and token storage for manual testing
- `output/proxy/` - Request/response history exports

## External Tool Requirements

This platform wraps external security tools that must be installed separately:

**Go Tools**:
- subfinder, amass, httpx, katana, gau, ffuf, nuclei, dalfox, subjack
- gobuster, gowitness

**Rust Tools**:
- feroxbuster

**Python Tools**:
- arjun, wafw00f, sqlmap, commix, dirsearch
- LinkFinder, SecretFinder (installed to ~/tools/)
- mitmproxy (interactive proxy)
- python-owasp-zap-v2.4 (ZAP API client)

**External Applications**:
- OWASP ZAP (snap, download, or Docker)

## Implementation Phases

### Completed
- **Phase 1**: Web Discovery & Reconnaissance (Gobuster, Dirsearch, LinkFinder, SecretFinder, GoWitness)
- **Passive Recon**: DNS enumeration, CT logs, WHOIS, Wayback Machine, OSINT/dorks
- **Phase 2**: Manual Testing Support & Proxy Integration (ZAP, RequestBuilder, SessionManager, PayloadEncoder)
- **Phase 3**: Advanced Injection Testing (NoSQL, LDAP, XPath injection + Advanced XSS with DOM/CSP bypass)

### Planned
- **Phase 3.5**: Advanced Web Vulnerabilities (SSRF, XXE, HTTP Smuggling, Race Conditions, CORS, File Upload)
- **Phase 4**: API & Modern Application Testing (Kiterunner, GraphQL, WebSocket, OpenAPI)
- **Phase 5**: Authentication & Authorization Testing (Auth bypass, IDOR, JWT attacks, Hydra)
- **Phase 6**: Reporting & Integration Enhancement (PDF reports, database storage, advanced analytics)

## Legal Notice

Only use on systems you own or have explicit written authorization to test. Passive reconnaissance tools query public databases only, but active scanning requires proper authorization.
