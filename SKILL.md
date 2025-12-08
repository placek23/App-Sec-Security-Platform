# AppSec Bounty Platform - Claude Code Skill

A comprehensive application security testing and bug bounty hunting platform designed for Claude Code integration.

## Quick Start Commands

### 🎯 Autonomous Bug Bounty Hunt (Recommended)
```bash
# Full automated assessment
python agents/bounty_hunter.py --target example.com

# With scope restrictions  
python agents/bounty_hunter.py --target example.com --scope "*.example.com" --out-of-scope "admin.example.com"

# Quick hunt (high severity only, 30 min max)
python agents/bounty_hunter.py --target example.com --severity high --max-time 1800
```

### 🔍 Reconnaissance Pipeline
```bash
# Complete recon (subdomains → probing → crawling → archive URLs)
python workflows/full_recon.py --target example.com

# Subdomain discovery only
python workflows/full_recon.py --target example.com --subdomain-only
```

### 🔴 Vulnerability Scanning
```bash
# Full vuln scan (WAF detection → nuclei → tech fingerprinting)
python workflows/vuln_scan.py --target example.com

# Scan multiple URLs
python workflows/vuln_scan.py --urls live_hosts.txt --severity high,critical

# With specific nuclei tags
python workflows/vuln_scan.py --target example.com --tags cve,sqli,xss
```

### 💉 Injection Testing
```bash
# Full injection test (SQLi, XSS, Command Injection, SSTI)
python workflows/injection_test.py --target "https://example.com/page?id=1"

# Test multiple URLs
python workflows/injection_test.py --urls urls_with_params.txt

# Single test type
python workflows/injection_test.py --target "https://example.com/search?q=test" --xss-only
python workflows/injection_test.py --target "https://example.com/page?id=1" --sqli-only
```

## Tool Reference by Phase

### Phase 1: Reconnaissance (5 tools)

| Tool | Wrapper | Usage |
|------|---------|-------|
| **subfinder** | `wrappers/recon/subfinder.py` | Passive subdomain enumeration |
| **amass** | `wrappers/recon/amass.py` | Advanced subdomain + OSINT |
| **httpx** | `wrappers/recon/httpx.py` | HTTP probing + tech detection |
| **katana** | `wrappers/recon/katana.py` | JS-aware web crawling |
| **gau** | `wrappers/recon/gau.py` | Archive URL harvesting |

```bash
# Individual tool examples
python wrappers/recon/subfinder.py -d example.com -o subs.txt --all
python wrappers/recon/amass.py -d example.com -passive -o amass.txt
python wrappers/recon/httpx.py -l subs.txt -o live.json --status-code --title --tech-detect
python wrappers/recon/katana.py -u https://example.com -d 3 -jc -o endpoints.txt
python wrappers/recon/gau.py -d example.com --subs -o archived.txt
```

### Phase 2: Content Discovery (4 tools)

| Tool | Wrapper | Usage |
|------|---------|-------|
| **ffuf** | `wrappers/discovery/ffuf.py` | Fast fuzzing |
| **feroxbuster** | `wrappers/discovery/feroxbuster.py` | Recursive discovery |
| **arjun** | `wrappers/discovery/arjun.py` | Parameter discovery |
| **paramspider** | `wrappers/discovery/paramspider.py` | Archive param mining |

```bash
# Individual tool examples
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w wordlist.txt -o dirs.json
python wrappers/discovery/feroxbuster.py -u https://example.com -d 3 -o ferox.txt
python wrappers/discovery/arjun.py -u https://example.com/api -o params.json
python wrappers/discovery/paramspider.py -d example.com -o params.txt
```

### Phase 3: Vulnerability Scanning (3 tools)

| Tool | Wrapper | Usage |
|------|---------|-------|
| **nuclei** | `wrappers/scanning/nuclei.py` | Template-based scanning |
| **wafw00f** | `wrappers/scanning/wafw00f.py` | WAF detection |
| **whatweb** | `wrappers/scanning/whatweb.py` | Tech fingerprinting |

```bash
# Individual tool examples
python wrappers/scanning/nuclei.py -l urls.txt -severity high,critical -o vulns.json
python wrappers/scanning/wafw00f.py -u https://example.com -a
python wrappers/scanning/whatweb.py -u https://example.com -a 3 -o tech.json
```

### Phase 4: Injection Testing (4 tools)

| Tool | Wrapper | Usage |
|------|---------|-------|
| **sqlmap** | `wrappers/injection/sqlmap.py` | SQL injection |
| **dalfox** | `wrappers/injection/dalfox.py` | XSS with DOM analysis |
| **commix** | `wrappers/injection/commix.py` | Command injection |
| **tplmap** | `wrappers/injection/tplmap.py` | SSTI exploitation |

```bash
# Individual tool examples
python wrappers/injection/sqlmap.py -u "https://example.com/page?id=1" --batch --dbs
python wrappers/injection/dalfox.py -u "https://example.com/search?q=test" --mining-all
python wrappers/injection/commix.py -u "https://example.com/ping?ip=127.0.0.1" --batch
python wrappers/injection/tplmap.py -u "https://example.com/render?name=test"
```

### Phase 5: Auth & API Testing (4 tools)

| Tool | Wrapper | Usage |
|------|---------|-------|
| **jwt_tool** | `wrappers/auth/jwt_tool.py` | JWT attacks |
| **subjack** | `wrappers/auth/subjack.py` | Subdomain takeover |
| **graphql_voyager** | `wrappers/api/graphql_voyager.py` | GraphQL testing |
| **testssl** | `wrappers/api/testssl.py` | SSL/TLS testing |

```bash
# Individual tool examples
python wrappers/auth/jwt_tool.py "eyJhbG..." -M at
python wrappers/auth/subjack.py -w subdomains.txt -o takeovers.txt
python wrappers/api/graphql_voyager.py -u https://example.com/graphql -o gql.json
python wrappers/api/testssl.py example.com -U -o ssl.json --json
```

## Workflow Pipeline Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    TARGET: example.com                           │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: RECONNAISSANCE                                         │
│  ┌──────────┐  ┌───────┐  ┌───────┐  ┌────────┐  ┌─────┐       │
│  │subfinder │→ │ amass │→ │ httpx │→ │ katana │→ │ gau │       │
│  └──────────┘  └───────┘  └───────┘  └────────┘  └─────┘       │
│  Output: subdomains.txt, live_hosts.txt, endpoints.txt          │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: CONTENT DISCOVERY                                      │
│  ┌──────┐  ┌─────────────┐  ┌───────┐  ┌─────────────┐         │
│  │ ffuf │→ │ feroxbuster │→ │ arjun │→ │ paramspider │         │
│  └──────┘  └─────────────┘  └───────┘  └─────────────┘         │
│  Output: directories.txt, parameters.txt                         │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 3: VULNERABILITY SCANNING                                 │
│  ┌─────────┐  ┌────────┐  ┌─────────┐                           │
│  │ wafw00f │→ │ nuclei │→ │ whatweb │                           │
│  └─────────┘  └────────┘  └─────────┘                           │
│  Output: waf_info.txt, vulnerabilities.json, technologies.txt   │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 4: INJECTION TESTING                                      │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐                │
│  │ sqlmap │→ │ dalfox │→ │ commix │→ │ tplmap │                │
│  └────────┘  └────────┘  └────────┘  └────────┘                │
│  Output: sqli.json, xss.json, cmdi.json, ssti.json              │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 5: AUTH & API TESTING                                     │
│  ┌──────────┐  ┌─────────┐  ┌─────────────────┐  ┌─────────┐   │
│  │ jwt_tool │→ │ subjack │→ │ graphql_voyager │→ │ testssl │   │
│  └──────────┘  └─────────┘  └─────────────────┘  └─────────┘   │
│  Output: jwt_vulns.json, takeovers.txt, gql.json, ssl.json      │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  REPORT GENERATION                                               │
│  HTML Report + JSON Export + Markdown Summary                    │
└─────────────────────────────────────────────────────────────────┘
```

## Python API Usage

```python
# Import wrappers
from wrappers.recon import SubfinderWrapper, HttpxWrapper
from wrappers.scanning import NucleiWrapper
from wrappers.injection import SqlmapWrapper, DalfoxWrapper

# Import workflows
from workflows import FullReconWorkflow, VulnScanWorkflow, InjectionTestWorkflow

# Import agent
from agents import BountyHunterAgent, AgentConfig

# Example: Run subdomain discovery
subfinder = SubfinderWrapper()
result = subfinder.run(target="example.com", all_sources=True)
print(f"Found {len(result['results'])} subdomains")

# Example: Run full recon workflow
recon = FullReconWorkflow(target="example.com", output_dir="./output/recon")
results = recon.run_full()

# Example: Run autonomous agent
config = AgentConfig(
    target="example.com",
    scope=["*.example.com"],
    severity_threshold="medium",
    max_time=3600
)
agent = BountyHunterAgent(config)
summary = agent.hunt()
```

## Output Files

All tools save output to `./output/` directory by default:

| Directory | Contents |
|-----------|----------|
| `output/recon/` | Subdomain lists, live hosts, crawled URLs |
| `output/scanning/` | Nuclei findings, WAF info, tech fingerprints |
| `output/injection/` | SQLi, XSS, command injection results |
| `output/auth/` | JWT issues, subdomain takeovers, SSL findings |
| `output/bounty_*/` | Full hunt results including HTML report |

## Report Formats

The platform generates three report formats:

1. **HTML** - Interactive report with severity filtering, executive summary
2. **JSON** - Machine-readable for integration with other tools
3. **Markdown** - Clean text format for documentation

## Configuration

Edit `config/tools.json` to customize:
- Tool binary paths
- Default arguments
- Rate limiting settings
- Timeout values

## Tips for Claude Code Integration

When using this platform with Claude Code:

1. **Start with recon**: Always begin with `full_recon.py` to discover the attack surface
2. **Check for WAFs**: Run `wafw00f` before intensive scanning to adjust rate limits
3. **Prioritize findings**: Focus on high/critical severity first
4. **Use the agent**: For comprehensive assessments, use `bounty_hunter.py`
5. **Review reports**: Check the HTML report for organized findings

## Legal Notice

⚠️ **IMPORTANT**: Only use this platform on systems you own or have explicit written authorization to test. Unauthorized security testing is illegal.
