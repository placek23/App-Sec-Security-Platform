"""
Subjack - Subdomain takeover vulnerability checker
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import AuthTool
from utils.output_parser import Finding, Severity


class SubjackWrapper(AuthTool):
    """Wrapper for subjack subdomain takeover tool"""
    
    @property
    def tool_name(self) -> str:
        return "subjack"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build subjack-specific arguments"""
        args = []
        
        # Input
        if kwargs.get("list"):
            args.extend(["-w", kwargs["list"]])
        else:
            # Create temp file for single domain
            args.extend(["-w", target])
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Threads
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["-timeout", str(kwargs["timeout"])])
        
        # Config (fingerprints)
        if kwargs.get("config"):
            args.extend(["-c", kwargs["config"]])
        
        # HTTPS
        if kwargs.get("ssl"):
            args.append("-ssl")
        
        # All results (not just vulnerable)
        if kwargs.get("all_results"):
            args.append("-a")
        
        # Manual mode
        if kwargs.get("manual"):
            args.append("-m")
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("-v")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse subjack output"""
        results = []
        
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Look for takeover indicators
            if "[VULNERABLE]" in line or "Takeover" in line or "vulnerable" in line.lower():
                # Extract domain from line
                parts = line.split()
                domain = ""
                service = "Unknown"
                
                for part in parts:
                    if "." in part and not part.startswith("["):
                        domain = part.strip("[]")
                        break
                
                # Try to identify the service
                services = ["github", "heroku", "aws", "azure", "shopify", "fastly", 
                           "pantheon", "tumblr", "wordpress", "ghost", "surge", "bitbucket"]
                for svc in services:
                    if svc in line.lower():
                        service = svc.title()
                        break
                
                results.append(Finding(
                    tool="subjack",
                    target=domain,
                    finding_type="subdomain_takeover",
                    title=f"Subdomain Takeover - {service}",
                    description=f"Subdomain {domain} is vulnerable to takeover via {service}",
                    severity=Severity.HIGH,
                    url=f"https://{domain}" if domain else "",
                    evidence=line
                ))
        
        return results


def main():
    parser = argparse.ArgumentParser(
        description="Subjack - Subdomain takeover detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subjack.py -w subdomains.txt
  python subjack.py -w subdomains.txt -t 100 -ssl -o takeovers.txt
  python subjack.py -w subdomains.txt -c fingerprints.json -v
        """
    )
    
    parser.add_argument("-w", "--wordlist", dest="list", required=True, help="File with subdomains")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    parser.add_argument("-c", "--config", help="Fingerprints config file")
    parser.add_argument("--ssl", action="store_true", help="Force HTTPS")
    parser.add_argument("-a", "--all", dest="all_results", action="store_true", help="Show all results")
    parser.add_argument("-m", "--manual", action="store_true", help="Manual mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    wrapper = SubjackWrapper()
    
    result = wrapper.run(
        target="",
        list=args.list,
        output_file=args.output,
        threads=args.threads,
        timeout=args.timeout,
        config=args.config,
        ssl=args.ssl,
        all_results=args.all_results,
        manual=args.manual,
        verbose=args.verbose
    )
    
    if result["success"]:
        findings = result["results"]
        if findings:
            print(f"\n[!] SUBDOMAIN TAKEOVER VULNERABILITIES FOUND: {len(findings)}")
            for finding in findings:
                print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
                print(f"  Domain: {finding.target}")
                print(f"  {finding.description}")
        else:
            print("\n[+] No subdomain takeover vulnerabilities detected")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
