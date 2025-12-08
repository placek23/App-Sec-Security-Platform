"""
Arjun - HTTP parameter discovery tool
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool
from utils.output_parser import OutputParser


class ArjunWrapper(DiscoveryTool):
    """Wrapper for arjun parameter discovery tool"""
    
    @property
    def tool_name(self) -> str:
        return "arjun"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build arjun-specific arguments"""
        args = []
        
        # Input
        if kwargs.get("urls_file"):
            args.extend(["-i", kwargs["urls_file"]])
        else:
            args.extend(["-u", target])
        
        # Output
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])
        
        # Output format
        if kwargs.get("output_format"):
            args.extend(["-oJ" if kwargs["output_format"] == "json" else "-oT"])
        
        # Method
        if kwargs.get("method"):
            args.extend(["-m", kwargs["method"]])
        
        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["--headers", header])
        
        # Include data
        if kwargs.get("include"):
            args.extend(["--include", kwargs["include"]])
        
        # Wordlist
        if kwargs.get("wordlist"):
            args.extend(["-w", kwargs["wordlist"]])
        
        # Threads
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])
        
        # Delay
        if kwargs.get("delay"):
            args.extend(["-d", str(kwargs["delay"])])
        
        # Timeout
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])
        
        # Passive mode (use web archives)
        if kwargs.get("passive"):
            args.append("--passive")
        
        # Stable mode
        if kwargs.get("stable"):
            args.append("--stable")
        
        # JSON params
        if kwargs.get("json_params"):
            args.append("-j")
        
        # Quiet mode
        if kwargs.get("quiet"):
            args.append("-q")
        
        return args
    
    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse arjun output"""
        return OutputParser.parse_arjun(stdout)


def main():
    parser = argparse.ArgumentParser(
        description="Arjun - HTTP parameter discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python arjun.py -u https://example.com/endpoint
  python arjun.py -u https://example.com/api -m POST -o params.json
  python arjun.py -i urls.txt -t 10 --passive
  python arjun.py -u https://example.com/search -w custom_params.txt
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL")
    group.add_argument("-i", "--input", dest="urls_file", help="File containing URLs")
    
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--output-format", choices=["json", "text"], default="json", help="Output format")
    parser.add_argument("-m", "--method", choices=["GET", "POST", "JSON"], help="HTTP method")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    parser.add_argument("--include", help="Data to include in every request")
    parser.add_argument("-w", "--wordlist", help="Custom parameter wordlist")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-d", "--delay", type=float, help="Delay between requests (seconds)")
    parser.add_argument("--timeout", type=int, help="Request timeout")
    parser.add_argument("--passive", action="store_true", help="Use web archives for discovery")
    parser.add_argument("--stable", action="store_true", help="Stable mode for flaky targets")
    parser.add_argument("-j", "--json", dest="json_params", action="store_true", help="Test JSON parameters")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    args = parser.parse_args()
    
    wrapper = ArjunWrapper()
    
    result = wrapper.run(
        target=args.url or "",
        output_file=args.output,
        urls_file=args.urls_file,
        output_format=args.output_format,
        method=args.method,
        headers=args.headers,
        include=args.include,
        wordlist=args.wordlist,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        passive=args.passive,
        stable=args.stable,
        json_params=args.json_params,
        quiet=args.quiet
    )
    
    if result["success"]:
        params = result["results"]
        print(f"\n[+] Found {len(params)} parameters:")
        for param in params:
            print(f"  - {param}")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
