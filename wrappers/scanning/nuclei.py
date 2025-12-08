"""
Nuclei - Fast vulnerability scanner with 4000+ templates
Enhanced with intelligent template selection profiles
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import ScanningTool
from utils.output_parser import OutputParser
from utils.nuclei_profiles import (
    NUCLEI_TEMPLATE_PROFILES, 
    get_profile, 
    list_profiles,
    recommend_profile,
    build_nuclei_args
)


class NucleiWrapper(ScanningTool):
    """
    Wrapper for nuclei vulnerability scanner.
    
    Supports 4000+ templates organized by:
    - Severity: info, low, medium, high, critical
    - Tags: cve, sqli, xss, rce, etc.
    - Profiles: quick, bounty, full, api, cloud, etc.
    """
    
    @property
    def tool_name(self) -> str:
        return "nuclei"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build nuclei-specific arguments"""
        args = []
        
        # Input - single target or list
        if kwargs.get("list"):
            args.extend(["-l", kwargs["list"]])
        else:
            args.extend(["-u", target])
        
        # === PROFILE-BASED CONFIGURATION ===
        # If a profile is specified, use it to set defaults
        profile_name = kwargs.get("profile")
        if profile_name:
            profile_args = build_nuclei_args(profile_name)
            # Apply profile settings as defaults (can be overridden)
            kwargs = {**profile_args, **kwargs}
        
        # === TEMPLATE SELECTION ===
        
        # Severity filter (most common way to filter)
        if kwargs.get("severity"):
            args.extend(["-severity", kwargs["severity"]])
        
        # Tags - include specific categories
        if kwargs.get("tags"):
            args.extend(["-tags", kwargs["tags"]])
        
        # Exclude tags
        if kwargs.get("exclude_tags"):
            args.extend(["-exclude-tags", kwargs["exclude_tags"]])
        
        # Specific template path
        if kwargs.get("templates"):
            args.extend(["-t", kwargs["templates"]])
        
        # Template IDs
        if kwargs.get("template_id"):
            args.extend(["-id", kwargs["template_id"]])
        
        # Exclude templates
        if kwargs.get("exclude_templates"):
            args.extend(["-exclude", kwargs["exclude_templates"]])
        
        # === OUTPUT ===
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # JSON output (recommended for parsing)
        if kwargs.get("json"):
            args.append("-jsonl")
        
        # Markdown export
        if kwargs.get("markdown"):
            args.extend(["-me", kwargs["markdown"]])
        
        # === PERFORMANCE & STEALTH ===
        
        # Rate limiting (requests per second)
        if kwargs.get("rate_limit"):
            args.extend(["-rl", str(kwargs["rate_limit"])])
        
        # Bulk size
        if kwargs.get("bulk_size"):
            args.extend(["-bs", str(kwargs["bulk_size"])])
        
        # Concurrency
        if kwargs.get("concurrency"):
            args.extend(["-c", str(kwargs["concurrency"])])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        
        # Retries
        if kwargs.get("retries"):
            args.extend(["-retries", str(kwargs["retries"])])
        
        # === REQUEST CUSTOMIZATION ===
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])
        
        # Custom header file
        if kwargs.get("header_file"):
            args.extend(["-header", kwargs["header_file"]])
        
        # Proxy
        if kwargs.get("proxy"):
            args.extend(["-proxy", kwargs["proxy"]])
        
        # User agent
        if kwargs.get("user_agent"):
            args.extend(["-H", f"User-Agent: {kwargs['user_agent']}"])
        
        # === ADVANCED OPTIONS ===
        
        # Headless browser for JS-heavy sites
        if kwargs.get("headless"):
            args.append("-headless")
        
        # System DNS resolution
        if kwargs.get("system_resolvers"):
            args.append("-sr")
        
        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.extend(["-fr"])
        
        # Max redirects
        if kwargs.get("max_redirects"):
            args.extend(["-mr", str(kwargs["max_redirects"])])
        
        # Interactsh server for OOB testing
        if kwargs.get("interactsh"):
            args.append("-iserver")
            args.append(kwargs["interactsh"])
        
        # Disable interactsh
        if kwargs.get("no_interactsh"):
            args.append("-ni")
        
        # === FILTERING ===
        
        # New templates only
        if kwargs.get("new_templates"):
            args.append("-nt")
        
        # Automatic scan (web scan optimization)
        if kwargs.get("automatic"):
            args.append("-as")
        
        # === OUTPUT CONTROL ===
        
        # Silent mode
        if kwargs.get("silent"):
            args.append("-silent")
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("-v")
        
        # No color
        args.append("-nc")
        
        # Stats
        if kwargs.get("stats"):
            args.append("-stats")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse nuclei output"""
        return OutputParser.parse_nuclei(stdout)
    
    def run_with_profile(self, target: str, profile: str = "bounty", **kwargs) -> dict:
        """
        Run nuclei with a predefined profile.
        
        Profiles:
        - quick: Critical issues only (~500 templates, 5-10 min)
        - bounty: Standard bug bounty (~1500 templates, 15-30 min)
        - full: All templates (~4000 templates, 1-2 hours)
        - cve: Known CVEs only (~2000 templates, 20-40 min)
        - owasp: OWASP Top 10 (~1000 templates, 15-25 min)
        - api: API security (~400 templates, 10-20 min)
        - cloud: Cloud misconfigs (~300 templates, 10-15 min)
        - injection: SQLi/XSS/RCE (~600 templates, 15-25 min)
        - stealth: Minimal footprint (~200 templates, 5-10 min)
        """
        return self.run(target=target, profile=profile, **kwargs)
    
    def smart_scan(self, target: str, target_info: dict = None, **kwargs) -> dict:
        """
        Intelligently select templates based on target context.
        
        Args:
            target: URL to scan
            target_info: Context dict with:
                - type: "webapp", "api", "cloud", "cms"
                - technology: detected tech stack
                - time_limit: minutes available
                - stealth: True for minimal footprint
                - bug_bounty: True for bounty-optimized scan
        """
        if target_info is None:
            target_info = {"bug_bounty": True, "time_limit": 30}
        
        recommended_profile = recommend_profile(target_info)
        profile = get_profile(recommended_profile)
        
        print(f"[*] Smart scan selected profile: {recommended_profile}")
        print(f"    {profile['description']}")
        print(f"    Templates: {profile['template_count']}")
        print(f"    Est. time: {profile['estimated_time']}")
        
        return self.run_with_profile(target, profile=recommended_profile, **kwargs)


def main():
    parser = argparse.ArgumentParser(
        description="Nuclei - Template-based vulnerability scanner (4000+ templates)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCANNING PROFILES:
  --profile quick      Critical only (~500 templates, 5-10 min)
  --profile bounty     Bug bounty optimized (~1500 templates, 15-30 min)
  --profile full       All templates (~4000 templates, 1-2 hours)
  --profile cve        Known CVEs (~2000 templates, 20-40 min)
  --profile owasp      OWASP Top 10 (~1000 templates, 15-25 min)
  --profile api        API security (~400 templates, 10-20 min)
  --profile cloud      Cloud misconfigs (~300 templates, 10-15 min)
  --profile injection  SQLi/XSS/RCE (~600 templates, 15-25 min)
  --profile stealth    Minimal footprint (~200 templates, 5-10 min)

Examples:
  # Quick scan - critical vulnerabilities only
  python nuclei.py -u https://example.com --profile quick
  
  # Standard bug bounty scan
  python nuclei.py -u https://example.com --profile bounty
  
  # Scan with specific tags
  python nuclei.py -u https://example.com --tags sqli,xss,rce
  
  # CVE-focused scan
  python nuclei.py -l urls.txt --profile cve -o results.json --json
  
  # Stealth scan with low rate
  python nuclei.py -u https://example.com --profile stealth -rl 5
  
  # Manual severity filter
  python nuclei.py -l urls.txt -severity high,critical -o vulns.json
        """
    )
    
    # Target
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Target URL")
    target_group.add_argument("-l", "--list", help="File containing URLs")
    target_group.add_argument("--list-profiles", action="store_true", help="List available profiles")
    
    # Profile selection (NEW!)
    parser.add_argument("--profile", choices=list(NUCLEI_TEMPLATE_PROFILES.keys()),
                       help="Use predefined scanning profile")
    
    # Template selection
    parser.add_argument("-severity", "--severity", help="Filter by severity (info,low,medium,high,critical)")
    parser.add_argument("--tags", help="Filter by tags (sqli,xss,cve,etc)")
    parser.add_argument("--exclude-tags", help="Exclude specific tags")
    parser.add_argument("-t", "--templates", help="Custom template path")
    parser.add_argument("--template-id", help="Specific template IDs")
    
    # Output
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--markdown", help="Markdown report path")
    
    # Performance
    parser.add_argument("-rl", "--rate-limit", type=int, help="Rate limit (req/sec)")
    parser.add_argument("-c", "--concurrency", type=int, help="Concurrent templates")
    parser.add_argument("-bs", "--bulk-size", type=int, help="Bulk size")
    parser.add_argument("--timeout", type=int, help="Request timeout")
    
    # Request options
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--user-agent", help="Custom user agent")
    
    # Advanced
    parser.add_argument("--headless", action="store_true", help="Enable headless browser")
    parser.add_argument("--no-interactsh", action="store_true", help="Disable OOB testing")
    parser.add_argument("--new-templates", action="store_true", help="Run new templates only")
    parser.add_argument("--automatic", action="store_true", help="Automatic web scan")
    
    # Output control
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--silent", action="store_true", help="Silent mode")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    
    args = parser.parse_args()
    
    # List profiles and exit
    if args.list_profiles:
        list_profiles()
        return 0
    
    wrapper = NucleiWrapper()
    
    result = wrapper.run(
        target=args.url or "",
        list=args.list,
        profile=args.profile,
        output_file=args.output,
        severity=args.severity,
        tags=args.tags,
        exclude_tags=args.exclude_tags,
        templates=args.templates,
        template_id=args.template_id,
        json=args.json,
        markdown=args.markdown,
        rate_limit=args.rate_limit,
        concurrency=args.concurrency,
        bulk_size=args.bulk_size,
        timeout=args.timeout,
        headers=args.headers,
        proxy=args.proxy,
        user_agent=args.user_agent,
        headless=args.headless,
        no_interactsh=args.no_interactsh,
        new_templates=args.new_templates,
        automatic=args.automatic,
        verbose=args.verbose,
        silent=args.silent,
        stats=args.stats
    )
    
    if result["success"]:
        findings = result["results"]
        if findings:
            print(f"\n[!] VULNERABILITIES FOUND: {len(findings)}")
            
            # Group by severity
            from collections import Counter
            severities = Counter(f.severity.value for f in findings)
            
            print(f"\n    Critical: {severities.get('critical', 0)}")
            print(f"    High: {severities.get('high', 0)}")
            print(f"    Medium: {severities.get('medium', 0)}")
            print(f"    Low: {severities.get('low', 0)}")
            print(f"    Info: {severities.get('info', 0)}")
            
            # Show top findings
            print(f"\n    Top findings:")
            for finding in findings[:10]:
                print(f"    [{finding.severity.value.upper()}] {finding.title}")
        else:
            print("\n[+] No vulnerabilities detected")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
