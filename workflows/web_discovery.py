#!/usr/bin/env python3
"""
Web Discovery Workflow - Phase 1
Combines multiple discovery tools for comprehensive web enumeration
"""
import sys
import os
import json
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.discovery.gobuster import GobusterWrapper
from wrappers.discovery.dirsearch_wrapper import DirsearchWrapper
from wrappers.discovery.linkfinder import LinkFinderWrapper
from wrappers.discovery.secretfinder import SecretFinderWrapper
from wrappers.discovery.gowitness import GoWitnessWrapper
from wrappers.discovery.ffuf import FfufWrapper


class WebDiscoveryWorkflow:
    """
    Comprehensive web discovery workflow combining Phase 1 tools:
    - Directory/file enumeration (Gobuster, Dirsearch, FFuf)
    - JavaScript analysis (LinkFinder, SecretFinder)
    - Visual reconnaissance (GoWitness)
    """

    def __init__(self, target: str, output_dir: str = None):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(output_dir or f"./output/discovery_{self.timestamp}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {
            "target": target,
            "timestamp": self.timestamp,
            "directories": [],
            "endpoints": [],
            "secrets": [],
            "screenshots": [],
            "summary": {}
        }

    def run_directory_enumeration(self, wordlist: str, extensions: str = None,
                                   threads: int = 10) -> dict:
        """Run directory enumeration with Gobuster"""
        print(f"\n[*] Starting directory enumeration on {self.target}")

        output_file = self.output_dir / "gobuster_results.txt"

        wrapper = GobusterWrapper()
        result = wrapper.run(
            target=self.target,
            wordlist=wordlist,
            extensions=extensions,
            threads=threads,
            output=str(output_file)
        )

        if result["success"]:
            self.results["directories"].extend(result.get("results", []))
            print(f"[+] Found {len(result.get('results', []))} directories/files")
        else:
            print(f"[-] Gobuster error: {result.get('error', 'Unknown')}")

        return result

    def run_path_discovery(self, extensions: str = "php,html,js,json",
                           recursive: bool = False) -> dict:
        """Run path discovery with Dirsearch"""
        print(f"\n[*] Starting path discovery on {self.target}")

        output_file = self.output_dir / "dirsearch_results.json"

        wrapper = DirsearchWrapper()
        result = wrapper.run(
            target=self.target,
            extensions=extensions,
            recursive=recursive,
            output=str(output_file),
            output_format="json"
        )

        if result["success"]:
            # Merge with existing directories (avoid duplicates)
            existing_urls = {d.get("url") for d in self.results["directories"]}
            for item in result.get("results", []):
                if item.get("url") not in existing_urls:
                    self.results["directories"].append(item)
            print(f"[+] Found {len(result.get('results', []))} paths")
        else:
            print(f"[-] Dirsearch error: {result.get('error', 'Unknown')}")

        return result

    def run_js_endpoint_discovery(self, js_urls: list = None) -> dict:
        """Find endpoints in JavaScript files"""
        print(f"\n[*] Starting JavaScript endpoint discovery")

        # If no JS URLs provided, try to find them from directory results
        if not js_urls:
            js_urls = [
                d.get("url") for d in self.results["directories"]
                if d.get("url", "").endswith(".js")
            ]
            # Also try common JS paths
            common_js = [
                f"{self.target}/app.js",
                f"{self.target}/main.js",
                f"{self.target}/bundle.js",
                f"{self.target}/static/js/main.js",
            ]
            js_urls.extend(common_js)

        all_endpoints = []
        wrapper = LinkFinderWrapper()

        for js_url in js_urls[:10]:  # Limit to first 10 JS files
            try:
                result = wrapper.run(target=js_url)
                if result["success"]:
                    all_endpoints.extend(result.get("results", []))
            except Exception as e:
                print(f"  [-] Error processing {js_url}: {e}")

        # Deduplicate endpoints
        seen = set()
        unique_endpoints = []
        for ep in all_endpoints:
            ep_str = ep.get("endpoint", "")
            if ep_str and ep_str not in seen:
                seen.add(ep_str)
                unique_endpoints.append(ep)

        self.results["endpoints"] = unique_endpoints
        print(f"[+] Found {len(unique_endpoints)} unique endpoints from JS files")

        return {"success": True, "results": unique_endpoints}

    def run_secret_discovery(self, js_urls: list = None) -> dict:
        """Find secrets in JavaScript files"""
        print(f"\n[*] Starting secret discovery in JavaScript files")

        # Use same JS URLs as endpoint discovery
        if not js_urls:
            js_urls = [
                d.get("url") for d in self.results["directories"]
                if d.get("url", "").endswith(".js")
            ]
            common_js = [
                f"{self.target}/app.js",
                f"{self.target}/main.js",
                f"{self.target}/config.js",
            ]
            js_urls.extend(common_js)

        all_secrets = []
        wrapper = SecretFinderWrapper()

        for js_url in js_urls[:10]:
            try:
                result = wrapper.run(target=js_url)
                if result["success"]:
                    for secret in result.get("results", []):
                        secret["source"] = js_url
                        all_secrets.append(secret)
            except Exception as e:
                print(f"  [-] Error processing {js_url}: {e}")

        self.results["secrets"] = all_secrets
        print(f"[+] Found {len(all_secrets)} potential secrets")

        return {"success": True, "results": all_secrets}

    def run_screenshots(self, urls: list = None) -> dict:
        """Take screenshots of discovered URLs"""
        print(f"\n[*] Taking screenshots")

        screenshot_dir = self.output_dir / "screenshots"
        screenshot_dir.mkdir(exist_ok=True)

        # Prepare URLs for screenshots
        if not urls:
            urls = [self.target]
            # Add interesting directories
            for d in self.results["directories"][:20]:
                url = d.get("url")
                if url and d.get("status_code") in [200, 301, 302]:
                    urls.append(url)

        # Write URLs to file
        urls_file = self.output_dir / "screenshot_urls.txt"
        with open(urls_file, "w") as f:
            f.write("\n".join(urls))

        wrapper = GoWitnessWrapper()
        result = wrapper.run(
            target="",
            file=str(urls_file),
            output_dir=str(screenshot_dir),
            threads=4
        )

        if result["success"]:
            self.results["screenshots"] = list(screenshot_dir.glob("*.png"))
            print(f"[+] Screenshots saved to {screenshot_dir}")
        else:
            print(f"[-] Screenshot error: {result.get('error', 'Unknown')}")

        return result

    def generate_summary(self) -> dict:
        """Generate workflow summary"""
        summary = {
            "target": self.target,
            "scan_time": self.timestamp,
            "total_directories": len(self.results["directories"]),
            "total_endpoints": len(self.results["endpoints"]),
            "total_secrets": len(self.results["secrets"]),
            "total_screenshots": len(self.results["screenshots"]),
            "high_value_findings": []
        }

        # Identify high-value findings
        # Sensitive directories
        sensitive_keywords = ["admin", "api", "config", "backup", "upload", "debug"]
        for d in self.results["directories"]:
            url = d.get("url", "").lower()
            if any(kw in url for kw in sensitive_keywords):
                summary["high_value_findings"].append({
                    "type": "sensitive_directory",
                    "url": d.get("url"),
                    "status": d.get("status_code")
                })

        # Critical secrets
        for s in self.results["secrets"]:
            if s.get("severity") in ["critical", "high"]:
                summary["high_value_findings"].append({
                    "type": "secret",
                    "secret_type": s.get("type"),
                    "severity": s.get("severity"),
                    "source": s.get("source")
                })

        self.results["summary"] = summary
        return summary

    def save_results(self) -> str:
        """Save all results to JSON file"""
        output_file = self.output_dir / "discovery_results.json"

        # Convert Path objects to strings for JSON serialization
        results_copy = self.results.copy()
        results_copy["screenshots"] = [str(s) for s in results_copy["screenshots"]]

        with open(output_file, "w") as f:
            json.dump(results_copy, f, indent=2, default=str)

        print(f"\n[+] Results saved to {output_file}")
        return str(output_file)

    def run_full_discovery(self, wordlist: str, extensions: str = "php,html,js",
                           run_screenshots: bool = True) -> dict:
        """Run the complete discovery workflow"""
        print(f"\n{'='*60}")
        print(f"Web Discovery Workflow - Target: {self.target}")
        print(f"{'='*60}")

        # Step 1: Directory enumeration
        self.run_directory_enumeration(wordlist, extensions)

        # Step 2: Path discovery
        self.run_path_discovery(extensions)

        # Step 3: JS endpoint discovery
        self.run_js_endpoint_discovery()

        # Step 4: Secret discovery
        self.run_secret_discovery()

        # Step 5: Screenshots (optional)
        if run_screenshots:
            self.run_screenshots()

        # Generate summary
        summary = self.generate_summary()

        # Save results
        self.save_results()

        # Print summary
        print(f"\n{'='*60}")
        print("Discovery Summary")
        print(f"{'='*60}")
        print(f"  Directories found: {summary['total_directories']}")
        print(f"  Endpoints found: {summary['total_endpoints']}")
        print(f"  Secrets found: {summary['total_secrets']}")
        print(f"  Screenshots taken: {summary['total_screenshots']}")
        print(f"  High-value findings: {len(summary['high_value_findings'])}")

        if summary["high_value_findings"]:
            print(f"\n[!] High-Value Findings:")
            for finding in summary["high_value_findings"][:10]:
                if finding["type"] == "sensitive_directory":
                    print(f"    [{finding['status']}] {finding['url']}")
                elif finding["type"] == "secret":
                    print(f"    [{finding['severity'].upper()}] {finding['secret_type']} in {finding['source']}")

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="Web Discovery Workflow - Comprehensive web enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_discovery.py -t https://example.com -w wordlist.txt
  python web_discovery.py -t https://example.com -w common.txt -e php,html,js
  python web_discovery.py -t https://example.com -w dirs.txt --no-screenshots
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist for directory enumeration")
    parser.add_argument("-e", "--extensions", default="php,html,js",
                        help="Extensions to search (default: php,html,js)")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--no-screenshots", action="store_true",
                        help="Skip screenshot capture")

    args = parser.parse_args()

    workflow = WebDiscoveryWorkflow(args.target, args.output)

    results = workflow.run_full_discovery(
        wordlist=args.wordlist,
        extensions=args.extensions,
        run_screenshots=not args.no_screenshots
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
