"""
GoWitness - Web screenshot tool
Takes screenshots of web pages for visual analysis
"""
import sys
import os
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import DiscoveryTool


class GoWitnessWrapper(DiscoveryTool):
    """Wrapper for gowitness screenshot tool"""

    @property
    def tool_name(self) -> str:
        return "gowitness"

    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build gowitness-specific arguments"""
        # Determine mode based on input
        if kwargs.get("file"):
            # File mode - screenshot URLs from file
            args = ["file", "-f", kwargs["file"]]
        elif kwargs.get("nmap"):
            # Nmap XML input
            args = ["nmap", "-f", kwargs["nmap"]]
        elif kwargs.get("scan"):
            # Scan mode
            args = ["scan", "--cidr", target]
        else:
            # Single URL mode
            args = ["single", target]

        # Output directory for screenshots
        if kwargs.get("output_dir"):
            args.extend(["-P", kwargs["output_dir"]])

        # Screenshot path (destination)
        if kwargs.get("screenshot_path"):
            args.extend(["--screenshot-path", kwargs["screenshot_path"]])

        # Timeout
        if kwargs.get("timeout"):
            args.extend(["--timeout", str(kwargs["timeout"])])

        # Delay between requests
        if kwargs.get("delay"):
            args.extend(["--delay", str(kwargs["delay"])])

        # Threads
        if kwargs.get("threads"):
            args.extend(["--threads", str(kwargs["threads"])])

        # User agent
        if kwargs.get("user_agent"):
            args.extend(["--user-agent", kwargs["user_agent"]])

        # Resolution
        if kwargs.get("resolution"):
            args.extend(["--resolution", kwargs["resolution"]])

        # Full page screenshot
        if kwargs.get("fullpage"):
            args.append("--fullpage")

        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["--header", header])

        # Proxy
        if kwargs.get("proxy"):
            args.extend(["--proxy", kwargs["proxy"]])

        # Chrome path
        if kwargs.get("chrome_path"):
            args.extend(["--chrome-path", kwargs["chrome_path"]])

        # Disable logging
        if kwargs.get("quiet"):
            args.append("--disable-logging")

        # JSON output
        if kwargs.get("json_output"):
            args.append("--json")

        # PDF mode
        if kwargs.get("pdf"):
            args.append("--pdf")

        # Skip status codes
        if kwargs.get("skip_status"):
            for status in kwargs["skip_status"]:
                args.extend(["--skip-status-code", str(status)])

        return args

    def parse_output(self, stdout: str, stderr: str) -> list:
        """Parse gowitness output"""
        results = []

        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Try to parse JSON output
            if line.startswith('{'):
                try:
                    data = json.loads(line)
                    results.append(data)
                    continue
                except json.JSONDecodeError:
                    pass

            # Parse text output
            if 'Screenshot' in line or 'http' in line.lower():
                results.append({"message": line})

        return results

    def generate_report(self, output_dir: str) -> str:
        """Generate HTML report from screenshots"""
        try:
            # Run gowitness report command
            import subprocess
            result = subprocess.run(
                ["gowitness", "report", "generate", "-P", output_dir],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                return os.path.join(output_dir, "report.html")
            return None
        except Exception:
            return None


def main():
    parser = argparse.ArgumentParser(
        description="GoWitness - Web screenshot tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gowitness.py -u https://example.com
  python gowitness.py -f urls.txt -P ./screenshots
  python gowitness.py --nmap scan.xml -P ./screenshots
  python gowitness.py -u https://example.com --fullpage --pdf
        """
    )

    parser.add_argument("-u", "--url", dest="target", help="Single target URL")
    parser.add_argument("-f", "--file", help="File containing URLs")
    parser.add_argument("--nmap", help="Nmap XML file")
    parser.add_argument("--scan", action="store_true", help="Scan mode with CIDR")
    parser.add_argument("-P", "--output-dir", default="./screenshots",
                        help="Output directory for screenshots")
    parser.add_argument("--screenshot-path", help="Custom screenshot path")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout per URL")
    parser.add_argument("--delay", type=int, help="Delay between screenshots")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads")
    parser.add_argument("--user-agent", help="Custom user agent")
    parser.add_argument("--resolution", default="1440x900", help="Screenshot resolution")
    parser.add_argument("--fullpage", action="store_true", help="Full page screenshot")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="Custom headers")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--chrome-path", help="Path to Chrome binary")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--json", action="store_true", dest="json_output", help="JSON output")
    parser.add_argument("--pdf", action="store_true", help="Save as PDF")
    parser.add_argument("--skip-status", type=int, nargs="+", help="Skip status codes")
    parser.add_argument("--report", action="store_true", help="Generate HTML report")

    args = parser.parse_args()

    if not args.target and not args.file and not args.nmap:
        parser.error("Either --url, --file, or --nmap is required")

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    wrapper = GoWitnessWrapper()

    result = wrapper.run(
        target=args.target or "",
        file=args.file,
        nmap=args.nmap,
        scan=args.scan,
        output_dir=args.output_dir,
        screenshot_path=args.screenshot_path,
        timeout=args.timeout,
        delay=args.delay,
        threads=args.threads,
        user_agent=args.user_agent,
        resolution=args.resolution,
        fullpage=args.fullpage,
        headers=args.headers,
        proxy=args.proxy,
        chrome_path=args.chrome_path,
        quiet=args.quiet,
        json_output=args.json_output,
        pdf=args.pdf,
        skip_status=args.skip_status
    )

    if result["success"]:
        print(f"\n[+] Screenshots saved to: {args.output_dir}")
        print(f"[+] Processed {len(result['results'])} URLs")

        # Generate report if requested
        if args.report:
            report_path = wrapper.generate_report(args.output_dir)
            if report_path:
                print(f"[+] Report generated: {report_path}")
            else:
                print("[-] Failed to generate report")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
