# ═══════════════════════════════════════════════════════════════════════════════
#                     APPSEC BOUNTY PLATFORM - COMMAND REFERENCE
# ═══════════════════════════════════════════════════════════════════════════════
# Quick reference for all platform commands
# Location: C:\Users\grzeg\Development\appsec-bounty-platform
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────────
#                              INITIAL SETUP
# ─────────────────────────────────────────────────────────────────────────────────

# Navigate to platform directory
cd C:\Users\grzeg\Development\appsec-bounty-platform

# Install Python dependencies
pip install -r requirements.txt

# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/OJ/gobuster/v3@latest
go install -v github.com/sensepost/gowitness@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/assetnote/kiterunner/cmd/kr@latest

# Install Python-based tools
pip install sqlmap wafw00f arjun paramspider
pip install python-owasp-zap-v2.4 mitmproxy
pip install dirsearch wfuzz
pip install pyjwt python-jose
pip install aiohttp websocket-client websockets
pip install reportlab weasyprint sqlalchemy jinja2

# Optional: Enhanced technology fingerprinting (Wappalyzer - 2000+ signatures)
pip install python-Wappalyzer setuptools

# Run phase-specific setup scripts
./scripts/setup_phase1.sh
./scripts/setup_phase2.sh
./scripts/setup_phase3.sh
./scripts/setup_phase4.sh
./scripts/setup_phase5.sh
./scripts/setup_phase6.sh

# Validate platform installation
python validate.py
python scripts/validate_phase1.py
python scripts/validate_phase2.py
python scripts/validate_phase3.py
python scripts/validate_phase4.py
python scripts/validate_phase5.py
python scripts/validate_phase6.py


# ─────────────────────────────────────────────────────────────────────────────────
#                            AUTONOMOUS AGENTS
# ─────────────────────────────────────────────────────────────────────────────────

# === BOUNTY HUNTER AGENT (Full Pipeline) ===

# Basic hunt
python agents/bounty_hunter.py --target example.com

# With scope filtering
python agents/bounty_hunter.py --target example.com --scope "*.example.com"

# Exclude out-of-scope domains
python agents/bounty_hunter.py --target example.com --scope "*.example.com" --out-of-scope "admin.example.com,staging.example.com"

# Only medium+ severity findings
python agents/bounty_hunter.py --target example.com --severity medium

# Time-limited hunt (1 hour max)
python agents/bounty_hunter.py --target example.com --max-time 3600

# Full featured hunt
python agents/bounty_hunter.py --target example.com --scope "*.example.com" --severity medium --max-time 7200 --no-parallel


# === VULNERABILITY SCANNER AGENT ===

# Quick scan (critical only)
python agents/vuln_scanner.py -t https://example.com --type quick

# Full scan
python agents/vuln_scanner.py -t https://example.com --type full

# Injection-focused scan
python agents/vuln_scanner.py -t https://example.com --type injection

# Nuclei-only scan
python agents/vuln_scanner.py -t https://example.com --type nuclei

# Scan from URL list
python agents/vuln_scanner.py -f urls.txt --type full

# With specific nuclei tags
python agents/vuln_scanner.py -t https://example.com --tags sqli,xss,rce

# With severity filter
python agents/vuln_scanner.py -t https://example.com --severity high,critical

# Custom rate limit
python agents/vuln_scanner.py -t https://example.com --rate 20


# ─────────────────────────────────────────────────────────────────────────────────
#                           AUTOMATED WORKFLOWS
# ─────────────────────────────────────────────────────────────────────────────────

# === PASSIVE RECONNAISSANCE WORKFLOW ===
# Safe for pre-engagement - Minimal direct target interaction

# Full passive recon (includes technology fingerprinting)
python workflows/passive_recon.py -d example.com

# Fully passive mode (no target requests)
python workflows/passive_recon.py -d example.com --skip-fingerprint

# Fingerprint specific URL
python workflows/passive_recon.py -d example.com -u https://example.com/app

# Skip Wayback Machine (faster)
python workflows/passive_recon.py -d example.com --skip-wayback

# With specific output directory
python workflows/passive_recon.py -d example.com -o ./output/passive_example


# === FULL RECONNAISSANCE WORKFLOW ===

# Complete recon pipeline
python workflows/full_recon.py --target example.com

# Subdomain discovery only
python workflows/full_recon.py --target example.com --subdomain-only

# HTTP probing only (requires subdomains.txt)
python workflows/full_recon.py --target example.com --probe-only

# Without parallel execution
python workflows/full_recon.py --target example.com --no-parallel

# Custom output directory
python workflows/full_recon.py --target example.com --output ./recon_results


# === WEB DISCOVERY WORKFLOW ===

# Combined web discovery (directory brute force, JS analysis, screenshots)
python workflows/web_discovery.py -u https://example.com

# With custom wordlist
python workflows/web_discovery.py -u https://example.com -w wordlists/large.txt

# Skip screenshots
python workflows/web_discovery.py -u https://example.com --no-screenshots


# === VULNERABILITY SCANNING WORKFLOW ===

# Full vuln scan
python workflows/vuln_scan.py --targets urls.txt

# Skip WAF detection
python workflows/vuln_scan.py --targets urls.txt --skip-waf

# Skip technology fingerprinting
python workflows/vuln_scan.py --targets urls.txt --skip-tech

# Specific severity only
python workflows/vuln_scan.py --targets urls.txt --severity high,critical

# With specific nuclei tags
python workflows/vuln_scan.py --targets urls.txt --tags cve,sqli,xss


# === INJECTION TESTING WORKFLOW ===

# Full injection testing
python workflows/injection_test.py --urls urls_with_params.txt

# SQL injection only
python workflows/injection_test.py --urls urls_with_params.txt --sqli-only

# XSS only
python workflows/injection_test.py --urls urls_with_params.txt --xss-only

# Command injection only
python workflows/injection_test.py --urls urls_with_params.txt --cmdi-only

# SSTI only
python workflows/injection_test.py --urls urls_with_params.txt --ssti-only


# === ADVANCED VULNERABILITIES WORKFLOW ===

# Full advanced vulnerability scan
python workflows/advanced_vulns.py -t "https://example.com"

# With OOB callback URL
python workflows/advanced_vulns.py -t "https://example.com/api" --callback http://your-callback.com

# Skip specific tests
python workflows/advanced_vulns.py -t "https://example.com" --skip ssrf,xxe


# === API TESTING WORKFLOW ===

# Full API security scan
python workflows/api_testing.py -t https://api.example.com

# Specific test types
python workflows/api_testing.py -t https://api.example.com --test discovery,openapi,graphql

# With authentication
python workflows/api_testing.py -t https://api.example.com -H "Authorization: Bearer token"


# === AUTHENTICATION TESTING WORKFLOW ===

# Full auth testing
python workflows/auth_testing.py -t https://example.com --login-url https://example.com/login

# With JWT token and API endpoint
python workflows/auth_testing.py -t https://example.com --login-url /login --api-url "/api/users/{id}" --jwt-token "eyJ..."

# Specific tests only
python workflows/auth_testing.py -t https://example.com --login-url /login --test-types bypass,idor


# ─────────────────────────────────────────────────────────────────────────────────
#                      PASSIVE RECONNAISSANCE TOOLS
# ─────────────────────────────────────────────────────────────────────────────────
#                   Safe for Pre-Engagement - No Target Contact

# === DNS ENUMERATION ===
python wrappers/passive/dns_enum.py -d example.com
python wrappers/passive/dns_enum.py -d example.com -o dns_records.json
python wrappers/passive/dns_enum.py -d example.com --record-types A,AAAA,MX,TXT,NS

# === CERTIFICATE TRANSPARENCY LOGS ===
python wrappers/passive/cert_transparency.py -d example.com
python wrappers/passive/cert_transparency.py -d example.com -o ct_subdomains.txt
python wrappers/passive/cert_transparency.py -d example.com --sources crtsh,certspotter

# === WHOIS LOOKUP ===
python wrappers/passive/whois_lookup.py -d example.com
python wrappers/passive/whois_lookup.py -d example.com -o whois_info.json
python wrappers/passive/whois_lookup.py -d example.com --historical

# === WAYBACK MACHINE (Historical URLs) ===
python wrappers/passive/wayback.py -d example.com
python wrappers/passive/wayback.py -d example.com -o wayback_urls.txt
python wrappers/passive/wayback.py -d example.com --filter-ext js,php,aspx

# === OSINT SEARCH & GOOGLE DORKS ===
python wrappers/passive/osint_search.py -d example.com
python wrappers/passive/osint_search.py -d example.com --google-dorks
python wrappers/passive/osint_search.py -d example.com --github-dorks
python wrappers/passive/osint_search.py -d example.com -o osint_results.json

# === TECHNOLOGY FINGERPRINTING (Wappalyzer-style) ===
# Detects web servers, frameworks, CMS, CDN, analytics, security tools, etc.
# Makes a single HTTP request like a normal browser visit
# Results auto-saved to ./output/tech_fingerprint/<domain>_<timestamp>.json
# Engines: builtin (~80 signatures), wappalyzer (2000+ signatures), both

python wrappers/passive/tech_fingerprint.py -u https://example.com                      # Auto-saves (builtin engine)
python wrappers/passive/tech_fingerprint.py -u https://example.com --engine wappalyzer  # Wappalyzer engine
python wrappers/passive/tech_fingerprint.py -u https://example.com --engine both        # Both engines combined
python wrappers/passive/tech_fingerprint.py -u https://example.com -o tech_results.json # Custom output file
python wrappers/passive/tech_fingerprint.py -u example.com --no-favicon                 # Skip favicon hash
python wrappers/passive/tech_fingerprint.py -u https://example.com --no-save            # Don't save (display only)
python wrappers/passive/tech_fingerprint.py -u https://example.com --json               # JSON output only
python wrappers/passive/tech_fingerprint.py -u https://example.com --timeout 30         # Custom timeout
python wrappers/passive/tech_fingerprint.py -u https://example.com --signatures custom_sigs.json


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 1: RECONNAISSANCE TOOLS
# ─────────────────────────────────────────────────────────────────────────────────

# === SUBFINDER (Passive Subdomain Discovery) ===
python wrappers/recon/subfinder.py -d example.com -o subs.txt
python wrappers/recon/subfinder.py -d example.com --all -o subs.txt              # All sources
python wrappers/recon/subfinder.py -d example.com --silent -o subs.txt           # Silent mode

# === AMASS (Advanced Subdomain Enumeration) ===
python wrappers/recon/amass.py -d example.com -o amass_subs.txt
python wrappers/recon/amass.py -d example.com -passive -o amass_subs.txt         # Passive only
python wrappers/recon/amass.py -d example.com -brute -o amass_subs.txt           # With brute force

# === HTTPX (HTTP Probing) ===
python wrappers/recon/httpx.py -l subdomains.txt -o live_hosts.txt
python wrappers/recon/httpx.py -u https://example.com --tech-detect              # Tech detection
python wrappers/recon/httpx.py -l subs.txt -sc -title -o results.json --json     # With status/title

# === KATANA (Web Crawler) ===
python wrappers/recon/katana.py -u https://example.com -o endpoints.txt
python wrappers/recon/katana.py -u https://example.com -d 3 -o endpoints.txt     # Depth 3
python wrappers/recon/katana.py -u https://example.com -jc -o endpoints.txt      # JS crawling

# === GAU (URL Harvesting from Archives) ===
python wrappers/recon/gau.py -d example.com -o archived_urls.txt
python wrappers/recon/gau.py -d example.com --providers wayback,commoncrawl      # Specific providers


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 1: WEB DISCOVERY TOOLS
# ─────────────────────────────────────────────────────────────────────────────────

# === GOBUSTER (Directory/File Brute Force) ===
python wrappers/discovery/gobuster.py -u https://example.com -w wordlists/common.txt
python wrappers/discovery/gobuster.py -u https://example.com -w wordlist.txt -x php,html,txt
python wrappers/discovery/gobuster.py -u https://example.com -w wordlist.txt -t 50           # 50 threads
python wrappers/discovery/gobuster.py -u https://example.com -w wordlist.txt -s 200,301,302  # Filter status

# === DIRSEARCH (Web Path Discovery) ===
python wrappers/discovery/dirsearch_wrapper.py -u https://example.com
python wrappers/discovery/dirsearch_wrapper.py -u https://example.com -e php,aspx,jsp
python wrappers/discovery/dirsearch_wrapper.py -u https://example.com -w wordlist.txt -r     # Recursive
python wrappers/discovery/dirsearch_wrapper.py -u https://example.com -t 30                  # 30 threads

# === FFUF (Directory/File Fuzzing) ===
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w wordlist.txt -o dirs.json
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w wordlist.txt -mc 200,301,302    # Filter codes
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w wordlist.txt -rate 50           # Rate limit
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w wordlist.txt -e .php,.html      # Extensions

# === FEROXBUSTER (Recursive Directory Brute Force) ===
python wrappers/discovery/feroxbuster.py -u https://example.com -o ferox_results.txt
python wrappers/discovery/feroxbuster.py -u https://example.com -w wordlist.txt -d 3             # Depth 3
python wrappers/discovery/feroxbuster.py -u https://example.com --rate 50                        # Rate limit

# === ARJUN (Hidden Parameter Discovery) ===
python wrappers/discovery/arjun.py -u https://example.com/page -o params.json
python wrappers/discovery/arjun.py -u https://example.com/page -m POST                           # POST method
python wrappers/discovery/arjun.py -u https://example.com/page --stable                          # Stable mode

# === PARAMSPIDER (Parameter Mining from Archives) ===
python wrappers/discovery/paramspider.py -d example.com -o params.txt
python wrappers/discovery/paramspider.py -d example.com --exclude woff,css,js                    # Exclude types

# === LINKFINDER (JavaScript Endpoint Extraction) ===
python wrappers/discovery/linkfinder.py -u https://example.com/app.js
python wrappers/discovery/linkfinder.py -u https://example.com/app.js -o endpoints.txt
python wrappers/discovery/linkfinder.py -u https://example.com/app.js -d example.com            # Filter domain

# === SECRETFINDER (Secret Detection in JavaScript) ===
python wrappers/discovery/secretfinder.py -u https://example.com/app.js
python wrappers/discovery/secretfinder.py -u https://example.com/app.js -o secrets.txt
python wrappers/discovery/secretfinder.py -u https://example.com/app.js -r custom_regex.txt     # Custom regex

# === GOWITNESS (Screenshot Capture) ===
python wrappers/discovery/gowitness.py -u https://example.com
python wrappers/discovery/gowitness.py -f urls.txt -o ./screenshots
python wrappers/discovery/gowitness.py -u https://example.com --timeout 30


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 2: PROXY & MANUAL TESTING TOOLS
# ─────────────────────────────────────────────────────────────────────────────────

# === ZAP INTEGRATION (OWASP ZAP Proxy) ===
# Note: Requires ZAP to be running (zap.sh -daemon -port 8080)

# Full scan (spider + active scan)
python wrappers/proxy/zap_integration.py --target https://example.com --full

# Spider only
python wrappers/proxy/zap_integration.py --target https://example.com --spider

# Active scan only (requires prior spidering)
python wrappers/proxy/zap_integration.py --target https://example.com --scan

# Spider and scan
python wrappers/proxy/zap_integration.py --target https://example.com --spider --scan

# Export reports
python wrappers/proxy/zap_integration.py --target https://example.com --full --report html
python wrappers/proxy/zap_integration.py --target https://example.com --full --report json
python wrappers/proxy/zap_integration.py --target https://example.com --full --report xml

# With custom API key
python wrappers/proxy/zap_integration.py --target https://example.com --full --api-key YOUR_API_KEY


# === REQUEST BUILDER (HTTP Request Building & Fuzzing) ===

# Basic request
python wrappers/proxy/request_builder.py --url https://example.com/api

# POST request with data
python wrappers/proxy/request_builder.py --url https://example.com/api --method POST --data '{"test": 1}'

# With custom headers
python wrappers/proxy/request_builder.py --url https://example.com/api --method POST --data '{"test": 1}' -H "Content-Type: application/json" -H "Authorization: Bearer token"

# Fuzz a parameter
python wrappers/proxy/request_builder.py --url "https://example.com/search?q=test" --fuzz-param q --wordlist wordlists/xss.txt

# Replay from history
python wrappers/proxy/request_builder.py --replay 0 --modify '{"data": "new_value"}'

# Export history to HAR
python wrappers/proxy/request_builder.py --export-har requests.har


# === SESSION MANAGER (Authentication Session Management) ===

# Create new session
python wrappers/proxy/session_manager.py --action create --name admin_session

# List all sessions
python wrappers/proxy/session_manager.py --action list

# Add token to session
python wrappers/proxy/session_manager.py --action add-token --name admin_session --token-name access_token --token-value "eyJ..." --token-type bearer

# Add API key
python wrappers/proxy/session_manager.py --action add-token --name admin_session --token-name api_key --token-value "sk-xxx" --token-type api_key

# Switch active session
python wrappers/proxy/session_manager.py --action switch --name admin_session

# Save sessions to file
python wrappers/proxy/session_manager.py --action save --file sessions.json

# Load sessions from file
python wrappers/proxy/session_manager.py --action load --file sessions.json

# Get auth headers for current session
python wrappers/proxy/session_manager.py --action headers


# === PAYLOAD ENCODER (Encoding for Bypass Testing) ===

# Basic encoding
python utils/encoder.py "<script>alert(1)</script>"

# URL encode
python utils/encoder.py "' OR 1=1--" --encode url

# Base64 encode
python utils/encoder.py "admin:password" --encode base64

# Chain encodings
python utils/encoder.py "' OR 1=1--" --encode url --encode base64

# HTML encode
python utils/encoder.py "<script>alert(1)</script>" --encode html

# Unicode encode
python utils/encoder.py "alert(1)" --encode unicode

# Hex encode
python utils/encoder.py "alert(1)" --encode hex

# XSS bypass variants
python utils/encoder.py --xss "<script>alert(1)</script>"

# SQL bypass variants
python utils/encoder.py --sql "' OR 1=1--"


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 3: VULNERABILITY SCANNING TOOLS
# ─────────────────────────────────────────────────────────────────────────────────

# === NUCLEI (Template-Based Scanner) ===

# List available profiles
python wrappers/scanning/nuclei.py --list-profiles

# Profile-based scanning (RECOMMENDED)
python wrappers/scanning/nuclei.py -u https://example.com --profile quick          # Critical only
python wrappers/scanning/nuclei.py -u https://example.com --profile bounty         # Bug bounty
python wrappers/scanning/nuclei.py -u https://example.com --profile full           # All templates
python wrappers/scanning/nuclei.py -u https://example.com --profile cve            # CVEs only
python wrappers/scanning/nuclei.py -u https://example.com --profile owasp          # OWASP Top 10
python wrappers/scanning/nuclei.py -u https://example.com --profile api            # API testing
python wrappers/scanning/nuclei.py -u https://example.com --profile cloud          # Cloud misconfigs
python wrappers/scanning/nuclei.py -u https://example.com --profile injection      # SQLi/XSS/RCE
python wrappers/scanning/nuclei.py -u https://example.com --profile stealth        # Minimal footprint

# CMS-specific profiles
python wrappers/scanning/nuclei.py -u https://example.com --profile wordpress
python wrappers/scanning/nuclei.py -u https://example.com --profile joomla
python wrappers/scanning/nuclei.py -u https://example.com --profile drupal

# Tech stack profiles
python wrappers/scanning/nuclei.py -u https://example.com --profile php
python wrappers/scanning/nuclei.py -u https://example.com --profile java
python wrappers/scanning/nuclei.py -u https://example.com --profile nodejs
python wrappers/scanning/nuclei.py -u https://example.com --profile python

# Manual severity filtering
python wrappers/scanning/nuclei.py -u https://example.com -severity high,critical
python wrappers/scanning/nuclei.py -l urls.txt -severity medium,high,critical -o results.json

# Tag-based filtering
python wrappers/scanning/nuclei.py -u https://example.com --tags sqli,xss,rce
python wrappers/scanning/nuclei.py -u https://example.com --tags cve --exclude-tags dos

# With rate limiting
python wrappers/scanning/nuclei.py -u https://example.com --profile bounty -rl 30

# === WAFW00F (WAF Detection) ===
python wrappers/scanning/wafw00f.py -u https://example.com
python wrappers/scanning/wafw00f.py -l urls.txt -o waf_results.txt
python wrappers/scanning/wafw00f.py -u https://example.com -a                      # Test all WAFs

# === WHATWEB (Technology Fingerprinting) ===
python wrappers/scanning/whatweb.py -u https://example.com
python wrappers/scanning/whatweb.py -u https://example.com -a 3                    # Aggressive
python wrappers/scanning/whatweb.py -l urls.txt -o tech.json --json


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 3: INJECTION TESTING TOOLS
# ─────────────────────────────────────────────────────────────────────────────────
#                   ⚠️  REQUIRES EXPLICIT AUTHORIZATION  ⚠️

# === SQLMAP (SQL Injection) ===
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --dbs           # Enumerate databases
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --tables -D db  # Enumerate tables
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --level 3       # Thorough testing
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --risk 2        # Risky payloads
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --tamper space2comment  # WAF bypass

# === DALFOX (XSS Scanner) ===
python wrappers/injection/dalfox.py -u "https://example.com/search?q=test"
python wrappers/injection/dalfox.py -u "https://example.com/search?q=test" --mining-all        # DOM mining
python wrappers/injection/dalfox.py -u "https://example.com/search?q=test" --blind https://callback.com  # Blind XSS
python wrappers/injection/dalfox.py -f urls.txt -o xss_results.json                            # Batch mode
python wrappers/injection/dalfox.py -u "https://example.com/search?q=test" -w 10               # 10 workers

# === COMMIX (Command Injection) ===
python wrappers/injection/commix.py -u "https://example.com/ping?host=127.0.0.1"
python wrappers/injection/commix.py -u "https://example.com/ping?host=127.0.0.1" --batch
python wrappers/injection/commix.py -u "https://example.com/ping?host=127.0.0.1" --os-cmd "whoami"
python wrappers/injection/commix.py -u "https://example.com/ping?host=127.0.0.1" --level 3     # Thorough

# === TPLMAP (SSTI - Template Injection) ===
python wrappers/injection/tplmap.py -u "https://example.com/page?name=test"
python wrappers/injection/tplmap.py -u "https://example.com/page?name=test" --os-shell         # OS shell
python wrappers/injection/tplmap.py -u "https://example.com/page?name=test" --os-cmd "id"
python wrappers/injection/tplmap.py -u "https://example.com/page?name=test" -e jinja2          # Specific engine

# === NOSQL INJECTION TESTER ===
python wrappers/injection/nosql_injection.py -u "https://example.com/api/users" -p username
python wrappers/injection/nosql_injection.py -u "https://example.com/login" --test-auth
python wrappers/injection/nosql_injection.py -u "https://example.com/api/search" -p query -m POST

# === LDAP INJECTION TESTER ===
python wrappers/injection/ldap_injection.py -u "https://example.com/search" -p query
python wrappers/injection/ldap_injection.py -u "https://example.com/auth" -p user --test-blind
python wrappers/injection/ldap_injection.py -u "https://example.com/ldap" -p username -m POST

# === XPATH INJECTION TESTER ===
python wrappers/injection/xpath_injection.py -u "https://example.com/xml" -p id
python wrappers/injection/xpath_injection.py -u "https://example.com/search" -p q --test-blind
python wrappers/injection/xpath_injection.py -u "https://example.com/query" -p xpath -m POST

# === ADVANCED XSS TESTER (DOM & CSP Bypass) ===
python wrappers/injection/advanced_xss.py -u "https://example.com/search" -p q
python wrappers/injection/advanced_xss.py -u "https://example.com/page" -p input --test-dom
python wrappers/injection/advanced_xss.py -u "https://example.com/app" -p data --test-csp


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 3.5: ADVANCED WEB VULNERABILITIES
# ─────────────────────────────────────────────────────────────────────────────────
#                   ⚠️  REQUIRES EXPLICIT AUTHORIZATION  ⚠️

# === SSRF TESTER (Server-Side Request Forgery) ===
python wrappers/advanced/ssrf_tester.py -u "https://example.com/fetch" -p url
python wrappers/advanced/ssrf_tester.py -u "https://example.com/proxy" -p target --test-type cloud
python wrappers/advanced/ssrf_tester.py -u "https://example.com/fetch" -p url --test-type internal
python wrappers/advanced/ssrf_tester.py -u "https://example.com/fetch" -p url --test-type bypass
python wrappers/advanced/ssrf_tester.py -u "https://example.com/fetch" -p url --callback http://your-callback.com

# === XXE INJECTOR (XML External Entity) ===
python wrappers/advanced/xxe_injector.py -u "https://example.com/api/xml"
python wrappers/advanced/xxe_injector.py -u "https://example.com/upload" --callback http://your-callback.com
python wrappers/advanced/xxe_injector.py -u "https://example.com/api/xml" --test-type blind
python wrappers/advanced/xxe_injector.py -u "https://example.com/api/xml" --test-type ssrf

# === HTTP REQUEST SMUGGLING ===
python wrappers/advanced/http_smuggler.py -u "https://example.com/"
python wrappers/advanced/http_smuggler.py -u "https://example.com/" --test-type clte
python wrappers/advanced/http_smuggler.py -u "https://example.com/" --test-type tecl
python wrappers/advanced/http_smuggler.py -u "https://example.com/" --test-type tete

# === RACE CONDITION TESTER ===
python wrappers/advanced/race_condition.py -u "https://example.com/redeem" -n 20
python wrappers/advanced/race_condition.py -u "https://example.com/vote" --test-type limit
python wrappers/advanced/race_condition.py -u "https://example.com/transfer" -m POST --data '{"amount": 100}' -n 50
python wrappers/advanced/race_condition.py -u "https://example.com/coupon" --expected-limit 1

# === CORS MISCONFIGURATION TESTER ===
python wrappers/advanced/cors_tester.py -u "https://example.com/api/data"
python wrappers/advanced/cors_tester.py -u "https://api.example.com/users" --origins "https://evil.com"
python wrappers/advanced/cors_tester.py -u "https://example.com/api" --test-all-origins

# === FILE UPLOAD BYPASS TESTER ===
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload"
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload" --param uploadFile
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload" --test-type double_extension
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload" --test-type content_type
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload" --test-type magic_bytes
python wrappers/advanced/file_upload_bypass.py -u "https://example.com/upload" --test-type all


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 4: API & MODERN APPLICATION TESTING
# ─────────────────────────────────────────────────────────────────────────────────

# === KITERUNNER (API Endpoint Discovery) ===
python wrappers/api/kiterunner.py -u https://api.example.com
python wrappers/api/kiterunner.py -u https://example.com -w /path/to/wordlist.txt
python wrappers/api/kiterunner.py -u https://example.com -A routes-large.kite        # Kitebuilder wordlist
python wrappers/api/kiterunner.py -u https://example.com --fallback                   # Fallback to ffuf if kr fails
python wrappers/api/kiterunner.py -u https://example.com -x 20                        # 20 concurrent requests

# === GRAPHQL TESTER (GraphQL Security Testing) ===
python wrappers/api/graphql_tester.py -u https://example.com/graphql
python wrappers/api/graphql_tester.py -u https://example.com/graphql --tests introspection
python wrappers/api/graphql_tester.py -u https://example.com/graphql --tests introspection,batch,depth
python wrappers/api/graphql_tester.py -u https://example.com/graphql --tests injection
python wrappers/api/graphql_tester.py -u https://example.com/graphql --tests dos --depth 15

# === WEBSOCKET TESTER (WebSocket Security Testing) ===
python wrappers/api/websocket_tester.py -u wss://example.com/ws
python wrappers/api/websocket_tester.py -u wss://example.com/ws --tests origin
python wrappers/api/websocket_tester.py -u wss://example.com/ws --tests auth
python wrappers/api/websocket_tester.py -u wss://example.com/ws --tests injection
python wrappers/api/websocket_tester.py -u wss://example.com/ws --tests origin,auth,injection
python wrappers/api/websocket_tester.py -u wss://example.com/ws --fuzz-payloads payloads.txt

# === OPENAPI ANALYZER (Swagger/OpenAPI Security Analysis) ===
python wrappers/api/openapi_analyzer.py -u https://api.example.com
python wrappers/api/openapi_analyzer.py -u https://api.example.com --spec swagger.json
python wrappers/api/openapi_analyzer.py -u https://api.example.com --spec swagger.json --test
python wrappers/api/openapi_analyzer.py --file openapi.yaml --analyze

# === JWT TESTER (JWT Security Testing) ===
python wrappers/api/jwt_tester.py -t "eyJhbGciOiJIUzI1NiIs..."
python wrappers/api/jwt_tester.py -t "eyJ..." --decode
python wrappers/api/jwt_tester.py -t "eyJ..." --url https://api.example.com/me
python wrappers/api/jwt_tester.py -t "eyJ..." --url https://api.example.com/me --wordlist jwt_secrets.txt
python wrappers/api/jwt_tester.py -t "eyJ..." --test-none
python wrappers/api/jwt_tester.py -t "eyJ..." --test-alg-confusion --public-key public.pem


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 5: AUTH & AUTHORIZATION TESTING
# ─────────────────────────────────────────────────────────────────────────────────
#                   ⚠️  REQUIRES EXPLICIT AUTHORIZATION  ⚠️

# === JWT_TOOL (JWT Token Analysis/Attacks) ===
python wrappers/auth/jwt_tool.py -t "eyJhbG..."                                    # Decode token
python wrappers/auth/jwt_tool.py -t "eyJhbG..." -M at                              # All tests
python wrappers/auth/jwt_tool.py -t "eyJhbG..." -C -d wordlist.txt                 # Crack secret
python wrappers/auth/jwt_tool.py -t "eyJhbG..." -X a                               # Algorithm confusion
python wrappers/auth/jwt_tool.py -t "eyJhbG..." -I -pc role -pv admin              # Inject claims

# === SUBJACK (Subdomain Takeover) ===
python wrappers/auth/subjack.py -w subdomains.txt -o takeovers.txt
python wrappers/auth/subjack.py -w subdomains.txt -ssl                             # Check HTTPS
python wrappers/auth/subjack.py -w subdomains.txt -c 50                            # 50 concurrent

# === AUTHENTICATION BYPASS TESTER ===
python wrappers/auth/auth_bypass.py -u https://example.com/login
python wrappers/auth/auth_bypass.py -u https://example.com/login --username-field user --password-field pass
python wrappers/auth/auth_bypass.py -u https://example.com/login --test-types sql
python wrappers/auth/auth_bypass.py -u https://example.com/login --test-types default
python wrappers/auth/auth_bypass.py -u https://example.com/login --test-types header
python wrappers/auth/auth_bypass.py -u https://example.com/login --test-types path
python wrappers/auth/auth_bypass.py -u https://example.com/login --test-types sql,default,header,path

# === IDOR TESTER (Insecure Direct Object Reference) ===
python wrappers/auth/idor_tester.py -u "https://api.example.com/users/{id}" -p id
python wrappers/auth/idor_tester.py -u "https://api.example.com/profile" -p user_id -t "Bearer token"
python wrappers/auth/idor_tester.py -u "https://api.example.com/profile" -p user_id --start-id 1 --count 50
python wrappers/auth/idor_tester.py -u "https://api.example.com/doc/{uuid}" --test-types uuid
python wrappers/auth/idor_tester.py -u "https://api.example.com/doc/{uuid}" --test-types uuid,path
python wrappers/auth/idor_tester.py -u "https://api.example.com/doc/{uuid}" --known-uuid "abc-123-def"

# === JWT ATTACKS TESTER ===
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --decode
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --test-types none
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --test-types weak
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --test-types kid
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --url https://api.example.com/me --test-types none,weak,kid
python wrappers/auth/jwt_attacks.py -t "eyJhbG..." --wordlist config/payloads/auth/jwt/common_secrets.txt

# === PRIVILEGE ESCALATION TESTER ===
python wrappers/auth/privilege_escalation.py -u https://example.com
python wrappers/auth/privilege_escalation.py -u https://example.com -t "Bearer low_priv_token"
python wrappers/auth/privilege_escalation.py -u https://example.com --test-types endpoint
python wrappers/auth/privilege_escalation.py -u https://example.com --test-types role
python wrappers/auth/privilege_escalation.py -u https://example.com --test-types param
python wrappers/auth/privilege_escalation.py -u https://example.com --test-types header
python wrappers/auth/privilege_escalation.py -u https://example.com --test-types endpoint,role,param,header

# === HYDRA WRAPPER (Password Brute Forcing) ===
# SSH brute force
python wrappers/auth/hydra_wrapper.py -t 192.168.1.1 -s ssh -l admin -P passwords.txt

# FTP brute force
python wrappers/auth/hydra_wrapper.py -t 192.168.1.1 -s ftp -L users.txt -P passwords.txt

# HTTP Basic Auth
python wrappers/auth/hydra_wrapper.py -t example.com -s http-get -l admin -P passwords.txt

# HTTP POST form brute force
python wrappers/auth/hydra_wrapper.py -t example.com -s http-post-form --form-path "/login" --form-data "user=^USER^&pass=^PASS^" --fail-string "Invalid" -L users.txt -P passwords.txt

# With rate limiting
python wrappers/auth/hydra_wrapper.py -t example.com -s ssh -l admin -P passwords.txt --rate 10


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 5: ADDITIONAL API TESTING TOOLS
# ─────────────────────────────────────────────────────────────────────────────────

# === GRAPHQL_VOYAGER (GraphQL Testing) ===
python wrappers/api/graphql_voyager.py -u https://example.com/graphql
python wrappers/api/graphql_voyager.py -u https://example.com/graphql --introspection  # Schema dump
python wrappers/api/graphql_voyager.py -u https://example.com/graphql --batch          # Batch queries
python wrappers/api/graphql_voyager.py -u https://example.com/graphql --all-tests      # All tests

# === TESTSSL (SSL/TLS Testing) ===
python wrappers/api/testssl.py -u example.com
python wrappers/api/testssl.py -u example.com --full                               # Full test
python wrappers/api/testssl.py -u example.com -o ssl_report.json --json
python wrappers/api/testssl.py -u example.com --vulnerable                         # Vuln checks only


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 6: REPORTING & INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────────

# === ADVANCED REPORTER (CVSS Scoring & Multi-Format Export) ===
python -c "
from utils.advanced_reporter import AdvancedReporter
reporter = AdvancedReporter(output_dir='./output/reports')
reporter.set_metadata(title='Security Assessment', target='example.com', tester='Security Team')
reporter.add_finding(title='SQL Injection', severity='critical', finding_type='sqli', tool='sqlmap', url='https://example.com/login')
reporter.export_all('example_report')
"

# === PDF REPORT GENERATOR ===
python utils/pdf_generator.py                                                     # Demo mode
python -c "
from utils.pdf_generator import PDFReportGenerator
generator = PDFReportGenerator()
report_data = {
    'title': 'Security Assessment',
    'target': 'example.com',
    'summary': {'severity_breakdown': {'critical': 1, 'high': 2}, 'total_findings': 3},
    'findings': [{'title': 'SQL Injection', 'severity': 'critical'}]
}
path = generator.generate(report_data)
print(f'PDF generated: {path}')
"

# === DATABASE MANAGER (Scan Persistence) ===
python database/manager.py                                                        # Demo mode
python -c "
from database.manager import DatabaseManager
db = DatabaseManager()
target = db.create_target('Example Corp', 'example.com')
scan = db.create_scan(target['id'], 'vulnerability_scan')
db.start_scan(scan['id'], tools=['nuclei', 'sqlmap'])
db.add_finding(scan['id'], 'SQL Injection', 'critical', finding_type='sqli')
db.complete_scan(scan['id'])
stats = db.get_summary_stats(target_id=target['id'])
print(stats)
"

# === SECURITY ANALYTICS ===
python utils/analytics.py                                                         # Demo mode
python -c "
from utils.analytics import SecurityAnalytics
analytics = SecurityAnalytics()
scans = [{'findings_count': 5, 'risk_score': 75, 'created_at': '2024-01-01'}]
findings = [{'severity': 'critical', 'finding_type': 'sqli'}]
report_data = analytics.generate_report_data(scans, findings)
print(f'Risk Score: {report_data[\"security_score\"][\"score\"]}')
print(f'Grade: {report_data[\"security_score\"][\"grade\"]}')
"

# === REPORT AGGREGATOR (Multi-Target) ===
python utils/report_aggregator.py                                                 # Demo mode
python -c "
from utils.report_aggregator import ReportAggregator
aggregator = ReportAggregator()
aggregator.add_scan_results('target1.com', scan={}, findings=[{'severity': 'high'}])
aggregator.add_scan_results('target2.com', scan={}, findings=[{'severity': 'critical'}])
paths = aggregator.export_all()
print(paths)
"

# === SCAN COMPARISON ===
python -c "
from utils.analytics import ComparisonReport
comparison = ComparisonReport()
scan1 = {'id': 1, 'findings': [{'title': 'XSS', 'severity': 'high'}]}
scan2 = {'id': 2, 'findings': [{'title': 'XSS', 'severity': 'high'}, {'title': 'SQLi', 'severity': 'critical'}]}
result = comparison.compare_scans(scan1, scan2)
print(f'New findings: {result[\"comparison\"][\"new_findings\"]}')
print(f'Resolved: {result[\"comparison\"][\"resolved_findings\"]}')
"


# ─────────────────────────────────────────────────────────────────────────────────
#                        NUCLEI TEMPLATE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────────

# Check template status
python utils/template_updater.py --status

# Update templates to latest
python utils/template_updater.py --update

# Backup templates before updating
python utils/template_updater.py --backup
python utils/template_updater.py --update

# List all backups
python utils/template_updater.py --list-backups

# Restore from backup
python utils/template_updater.py --restore templates_20240101_120000

# Search for templates
python utils/template_updater.py --search wordpress
python utils/template_updater.py --search "sql injection" --content

# Show new templates (last 7 days)
python utils/template_updater.py --new

# Add custom template
python utils/template_updater.py --add my_template.yaml --category custom

# List nuclei profiles
python utils/nuclei_profiles.py --list

# Get profile info
python utils/nuclei_profiles.py --info wordpress


# ─────────────────────────────────────────────────────────────────────────────────
#                           UTILITY COMMANDS
# ─────────────────────────────────────────────────────────────────────────────────

# Validate platform installation
python validate.py

# Validate specific phases
python scripts/validate_phase1.py
python scripts/validate_phase2.py
python scripts/validate_phase3.py
python scripts/validate_phase4.py
python scripts/validate_phase5.py
python scripts/validate_phase6.py

# Test phase implementations
python scripts/test_phase1.py

# Generate HTML report
python -c "from utils.reporter import Reporter; Reporter.generate_html_report(findings, 'report.html')"

# Parse nuclei output
python -c "from utils.output_parser import OutputParser; OutputParser.parse_nuclei(open('nuclei.json').read())"

# Initialize database
python -c "from database.models import init_db; init_db()"


# ─────────────────────────────────────────────────────────────────────────────────
#                          COMMON WORKFLOWS
# ─────────────────────────────────────────────────────────────────────────────────

# === WORKFLOW 1: Quick Assessment (30 minutes) ===
python wrappers/recon/subfinder.py -d target.com -o subs.txt
python wrappers/recon/httpx.py -l subs.txt -o live.txt
python wrappers/scanning/nuclei.py -l live.txt --profile quick -o vulns.json

# === WORKFLOW 2: Standard Bug Bounty Hunt (2-3 hours) ===
python workflows/full_recon.py --target target.com
python workflows/vuln_scan.py --targets output/live_hosts.txt
python workflows/injection_test.py --urls output/urls_with_params.txt

# === WORKFLOW 3: Stealth Reconnaissance ===
# Fully passive - No direct target contact
python workflows/passive_recon.py -d target.com --skip-fingerprint
python wrappers/passive/cert_transparency.py -d target.com
python wrappers/passive/wayback.py -d target.com
python wrappers/passive/osint_search.py -d target.com --google-dorks

# === WORKFLOW 3b: Tech-Enhanced Passive Recon ===
# Single request to target for technology detection
python workflows/passive_recon.py -d target.com
python wrappers/passive/tech_fingerprint.py -u https://target.com -o tech.json

# === WORKFLOW 4: Full Autonomous Hunt ===
python agents/bounty_hunter.py --target target.com --scope "*.target.com" --severity medium --max-time 7200

# === WORKFLOW 5: API Security Assessment ===
python workflows/api_testing.py -t https://api.target.com
python wrappers/api/openapi_analyzer.py -u https://api.target.com
python wrappers/api/graphql_tester.py -u https://api.target.com/graphql

# === WORKFLOW 6: Authentication Testing ===
python workflows/auth_testing.py -t https://target.com --login-url https://target.com/login
python wrappers/auth/auth_bypass.py -u https://target.com/login
python wrappers/auth/idor_tester.py -u "https://api.target.com/users/{id}" -p id

# === WORKFLOW 7: Advanced Vulnerability Hunt ===
python workflows/advanced_vulns.py -t "https://target.com"
python wrappers/advanced/ssrf_tester.py -u "https://target.com/fetch" -p url
python wrappers/advanced/xxe_injector.py -u "https://target.com/api/xml"


# ─────────────────────────────────────────────────────────────────────────────────
#                           OUTPUT FILE LOCATIONS
# ─────────────────────────────────────────────────────────────────────────────────
#
# Default output directory: ./output/
#
# Passive Reconnaissance:
#   - output/passive_*/       (all passive recon results)
#   - dns_records.json        (DNS enumeration)
#   - ct_subdomains.txt       (Certificate Transparency)
#   - whois_info.json         (WHOIS data)
#   - wayback_urls.txt        (Wayback Machine URLs)
#   - osint_results.json      (OSINT/dork results)
#   - tech_fingerprint.json   (technology detection - in workflow)
#
# Technology Fingerprinting (standalone):
#   - output/tech_fingerprint/<domain>_<timestamp>.json
#
# Active Reconnaissance:
#   - subdomains.txt          (discovered subdomains)
#   - live_hosts.txt          (HTTP-responsive hosts)
#   - endpoints.txt           (crawled URLs)
#   - urls_with_params.txt    (URLs with parameters)
#
# Web Discovery:
#   - output/discovery/       (directory brute force results)
#   - js_endpoints.txt        (JavaScript endpoints)
#   - secrets.txt             (detected secrets)
#   - output/screenshots/     (captured screenshots)
#
# Scanning:
#   - nuclei_results.json     (vulnerability findings)
#   - waf_detection.txt       (WAF information)
#   - tech_stack.json         (technology fingerprints)
#
# Injection Testing:
#   - output/injection/       (SQLi, XSS, command injection results)
#
# API Testing:
#   - api_endpoints.json      (discovered API endpoints)
#   - graphql_schema.json     (GraphQL introspection)
#   - openapi_analysis.json   (OpenAPI security analysis)
#
# Auth Testing:
#   - auth_bypass_results.json
#   - idor_results.json
#   - jwt_analysis.json
#
# Proxy & Sessions:
#   - output/zap/             (ZAP scan reports)
#   - output/sessions/        (saved sessions)
#   - output/proxy/           (request/response history)
#
# Reports:
#   - output/reports/         (generated reports)
#   - report.html             (HTML report)
#   - report.pdf              (PDF report)
#   - report.json             (JSON report)
#   - report.md               (Markdown report)
#
# Database:
#   - output/appsec_bounty.db (SQLite database)
#
# Bounty Hunts:
#   - output/bounty_*/        (full hunt results with report)
#
# ─────────────────────────────────────────────────────────────────────────────────
