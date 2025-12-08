"""
Gobuster - Directory/file brute forcing tool
"""
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool


class GobusterWrapper(DiscoveryTool):
    """Wrapper for gobuster directory/file brute forcing tool"""

    @property
    def tool_name(self) -> str:
        return "gobuster"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build gobuster-specific arguments"""
        # Determine mode (default: dir)
        mode = kwargs.get("mode", "dir")
        args = [mode, "-u", target]

        # Wordlist (required for dir mode)
        if kwargs.get("wordlist"):
            args.extend(["-w", kwargs["wordlist"]])

        # Extensions
        if kwargs.get("extensions"):
            args.extend(["-x", kwargs["extensions"]])

        # Threads
        if kwargs.get("threads"):
            args.extend(["-t", str(kwargs["threads"])])

        # Status codes to match
        if kwargs.get("status_codes"):
            args.extend(["-s", kwargs["status_codes"]])

        # Status codes to exclude
        if kwargs.get("exclude_codes"):
            args.extend(["-b", kwargs["exclude_codes"]])

        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("-r")

        # Add trailing slash
        if kwargs.get("add_slash"):
            args.append("-f")

        # Expanded mode
        if kwargs.get("expanded"):
            args.append("-e")

        # Quiet mode (no banner)
        if kwargs.get("quiet"):
            args.append("-q")

        # Verbose
        if kwargs.get("verbose"):
            args.append("-v")

        # Timeout
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])

        # User agent
        if kwargs.get("user_agent"):
            args.extend(["-a", kwargs["user_agent"]])

        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])

        # Cookies
        if kwargs.get("cookies"):
            args.extend(["-c", kwargs["cookies"]])

        # Output file
        if kwargs.get("output"):
            args.extend(["-o", kwargs["output"]])

        # Proxy
        if kwargs.get("proxy"):
            args.extend(["-p", kwargs["proxy"]])

        # No TLS validation
        if kwargs.get("insecure"):
            args.append("-k")

        # Wildcard responses
        if kwargs.get("wildcard"):
            args.append("--wildcard")

        # No color
        args.append("--no-color")

        return args

    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse gobuster output"""
        results = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('=') and '/' in line:
                # Parse lines like: /admin (Status: 200) [Size: 1234]
                parts = line.split()
                if parts:
                    result = {"url": parts[0]}
                    # Try to extract status code
                    if "(Status:" in line:
                        try:
                            status_start = line.index("(Status:") + 8
                            status_end = line.index(")", status_start)
                            result["status_code"] = int(line[status_start:status_end].strip())
                        except (ValueError, IndexError):
                            pass
                    # Try to extract size
                    if "[Size:" in line:
                        try:
                            size_start = line.index("[Size:") + 6
                            size_end = line.index("]", size_start)
                            result["size"] = int(line[size_start:size_end].strip())
                        except (ValueError, IndexError):
                            pass
                    results.append(result)
        return results


def main():
    parser = argparse.ArgumentParser(
        description="Gobuster - Directory/file brute forcing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gobuster.py -u https://example.com -w wordlist.txt
  python gobuster.py -u https://example.com -w dirs.txt -x php,html -t 50
  python gobuster.py -u https://example.com -w dirs.txt -s 200,204,301 -o results.txt
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist path")
    parser.add_argument("-m", "--mode", default="dir", choices=["dir", "dns", "vhost", "fuzz"], help="Gobuster mode")
    parser.add_argument("-x", "--extensions", help="Extensions to search (e.g., php,html,js)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-s", "--status-codes", help="Status codes to match (e.g., 200,204,301)")
    parser.add_argument("-b", "--exclude-codes", help="Status codes to exclude (e.g., 404)")
    parser.add_argument("-r", "--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("-f", "--add-slash", action="store_true", help="Add trailing slash")
    parser.add_argument("-e", "--expanded", action="store_true", help="Expanded mode")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, help="HTTP timeout")
    parser.add_argument("-a", "--user-agent", help="User agent string")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    parser.add_argument("-c", "--cookies", help="Cookies to use")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--wildcard", action="store_true", help="Force wildcard processing")

    args = parser.parse_args()

    wrapper = GobusterWrapper()

    result = wrapper.run(
        target=args.url,
        output_file=args.output,
        mode=args.mode,
        wordlist=args.wordlist,
        extensions=args.extensions,
        threads=args.threads,
        status_codes=args.status_codes,
        exclude_codes=args.exclude_codes,
        follow_redirects=args.follow_redirects,
        add_slash=args.add_slash,
        expanded=args.expanded,
        quiet=args.quiet,
        verbose=args.verbose,
        timeout=args.timeout,
        user_agent=args.user_agent,
        headers=args.headers,
        cookies=args.cookies,
        proxy=args.proxy,
        insecure=args.insecure,
        wildcard=args.wildcard
    )

    if result["success"]:
        print(f"\n[+] Found {len(result['results'])} entries")
        for entry in result["results"][:20]:
            status = f"[{entry.get('status_code', '?')}]" if entry.get('status_code') else ""
            size = f"[{entry.get('size', '?')} bytes]" if entry.get('size') else ""
            print(f"  {status} {entry.get('url', '')} {size}")
        if len(result["results"]) > 20:
            print(f"  ... and {len(result['results']) - 20} more")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
