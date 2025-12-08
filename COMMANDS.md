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
go install -v github.com/epi052/feroxbuster@latest

# Install Python-based tools
pip install sqlmap wafw00f arjun paramspider

# Validate platform installation
python validate.py


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
#                      PHASE 2: CONTENT DISCOVERY TOOLS
# ─────────────────────────────────────────────────────────────────────────────────

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
#                      PHASE 4: INJECTION TESTING TOOLS
# ─────────────────────────────────────────────────────────────────────────────────
#                   ⚠️  REQUIRES EXPLICIT AUTHORIZATION  ⚠️
# ─────────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────────
#                      PHASE 5: AUTH & API TESTING TOOLS
# ─────────────────────────────────────────────────────────────────────────────────

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

# Generate HTML report
python -c "from utils.reporter import Reporter; Reporter.generate_html_report(findings, 'report.html')"

# Parse nuclei output
python -c "from utils.output_parser import OutputParser; OutputParser.parse_nuclei(open('nuclei.json').read())"


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
python wrappers/recon/subfinder.py -d target.com -o subs.txt --silent
python wrappers/recon/gau.py -d target.com -o archived.txt
python wrappers/discovery/paramspider.py -d target.com -o params.txt
# Above 3 commands are 100% passive - no target contact

# === WORKFLOW 4: Full Autonomous Hunt ===
python agents/bounty_hunter.py --target target.com --scope "*.target.com" --severity medium --max-time 7200


# ─────────────────────────────────────────────────────────────────────────────────
#                           OUTPUT FILE LOCATIONS
# ─────────────────────────────────────────────────────────────────────────────────
#
# Default output directory: ./output/
#
# Reconnaissance:
#   - subdomains.txt      (discovered subdomains)
#   - live_hosts.txt      (HTTP-responsive hosts)
#   - endpoints.txt       (crawled URLs)
#   - urls_with_params.txt (URLs with parameters)
#
# Scanning:
#   - nuclei_results.json (vulnerability findings)
#   - waf_detection.txt   (WAF information)
#   - tech_stack.json     (technology fingerprints)
#
# Reports:
#   - report.html         (HTML report with findings)
#   - report.json         (JSON report)
#   - report.md           (Markdown report)
#
# ─────────────────────────────────────────────────────────────────────────────────
