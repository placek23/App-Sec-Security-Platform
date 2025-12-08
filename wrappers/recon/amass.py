"""
Amass - Advanced subdomain enumeration and OSINT gathering
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import ReconTool
from utils.output_parser import OutputParser


class AmassWrapper(ReconTool):
    """Wrapper for amass subdomain enumeration tool"""
    
    @property
    def tool_name(self) -> str:
        return "amass"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build amass-specific arguments"""
        mode = kwargs.get("mode", "enum")
        args = [mode]
        
        if mode == "enum":
            args.extend(["-d", target])
            
            # Passive only
            if kwargs.get("passive", True):
                args.append("-passive")
            
            # Active mode
            if kwargs.get("active"):
                args.append("-active")
            
            # Brute force
            if kwargs.get("brute"):
                args.append("-brute")
                if kwargs.get("wordlist"):
                    args.extend(["-w", kwargs["wordlist"]])
            
            # Output file
            if kwargs.get("output"):
                args.extend(["-o", kwargs["output"]])
            
            # Config file
            if kwargs.get("config"):
                args.extend(["-config", kwargs["config"]])
            
            # Max DNS queries
            if kwargs.get("max_dns"):
                args.extend(["-max-dns-queries", str(kwargs["max_dns"])])
            
            # Timeout
            if kwargs.get("timeout"):
                args.extend(["-timeout", str(kwargs["timeout"])])
        
        elif mode == "intel":
            # Intelligence gathering mode
            if kwargs.get("asn"):
                args.extend(["-asn", kwargs["asn"]])
            if kwargs.get("cidr"):
                args.extend(["-cidr", kwargs["cidr"]])
            if kwargs.get("org"):
                args.extend(["-org", kwargs["org"]])
            if kwargs.get("whois"):
                args.append("-whois")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse amass output"""
        return OutputParser.parse_amass(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="Amass - Advanced subdomain enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python amass.py -d example.com
  python amass.py -d example.com --passive -o subdomains.txt
  python amass.py -d example.com --brute -w wordlist.txt
  python amass.py --mode intel --asn 12345
        """
    )
    
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--mode", choices=["enum", "intel"], default="enum", help="Amass mode")
    parser.add_argument("--passive", action="store_true", default=True, help="Passive enumeration only")
    parser.add_argument("--active", action="store_true", help="Include active techniques")
    parser.add_argument("--brute", action="store_true", help="Enable brute forcing")
    parser.add_argument("-w", "--wordlist", help="Wordlist for brute forcing")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--max-dns", type=int, help="Maximum DNS queries per minute")
    parser.add_argument("--timeout", type=int, help="Timeout in minutes")
    parser.add_argument("--asn", help="ASN for intel mode")
    parser.add_argument("--cidr", help="CIDR for intel mode")
    parser.add_argument("--org", help="Organization for intel mode")
    parser.add_argument("--whois", action="store_true", help="WHOIS lookups")
    
    args = parser.parse_args()
    
    if args.mode == "enum" and not args.domain:
        parser.error("Domain (-d) is required for enum mode")
    
    wrapper = AmassWrapper()
    
    result = wrapper.run(
        target=args.domain or "",
        output_file=args.output,
        mode=args.mode,
        passive=args.passive,
        active=args.active,
        brute=args.brute,
        wordlist=args.wordlist,
        config=args.config,
        max_dns=args.max_dns,
        timeout=args.timeout,
        asn=args.asn,
        cidr=args.cidr,
        org=args.org,
        whois=args.whois
    )
    
    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} subdomains")
        for subdomain in result["results"][:20]:
            print(f"  {subdomain.domain}")
        if len(result["results"]) > 20:
            print(f"  ... and {len(result['results']) - 20} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
