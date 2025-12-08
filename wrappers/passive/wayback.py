#!/usr/bin/env python3
"""
Wayback Machine - Historical URL and content discovery
Queries Internet Archive for historical snapshots
"""
import sys
import json
import argparse
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, quote
import requests

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class WaybackMachine:
    """
    Wayback Machine (Internet Archive) query tool.

    Completely passive - queries archived data, no target interaction.

    Features:
    - Historical URL discovery
    - Find old/removed endpoints
    - Discover hidden parameters
    - Find old JavaScript files
    - Content change detection
    """

    CDX_API = "https://web.archive.org/cdx/search/cdx"
    AVAILABILITY_API = "https://archive.org/wayback/available"
    SAVE_API = "https://web.archive.org/save"  # Not used - would be active

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.results = {
            'urls': [],
            'snapshots': [],
            'parameters': set(),
            'endpoints': set(),
            'files': {
                'js': [],
                'json': [],
                'xml': [],
                'config': []
            },
            'metadata': {}
        }

    def query_cdx(self, url: str, match_type: str = 'prefix',
                  limit: int = 10000, filters: List[str] = None) -> List[Dict]:
        """
        Query Wayback Machine CDX API for URL history.

        match_type options:
        - 'exact': Exact URL match
        - 'prefix': URL prefix match (default)
        - 'host': All URLs from host
        - 'domain': All URLs from domain and subdomains
        """
        params = {
            'url': url,
            'output': 'json',
            'matchType': match_type,
            'limit': limit,
            'fl': 'timestamp,original,mimetype,statuscode,digest,length'
        }

        if filters:
            params['filter'] = filters

        try:
            response = requests.get(self.CDX_API, params=params, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if data and len(data) > 1:
                    headers = data[0]
                    results = []
                    for row in data[1:]:
                        results.append(dict(zip(headers, row)))
                    return results
        except Exception as e:
            print(f"  [!] CDX API error: {e}")

        return []

    def get_snapshots(self, url: str, limit: int = 1000) -> List[Dict]:
        """Get all archived snapshots for a URL."""
        print(f"[*] Querying Wayback Machine for {url}...")
        snapshots = self.query_cdx(url, match_type='prefix', limit=limit)
        print(f"    Found {len(snapshots)} snapshots")
        return snapshots

    def extract_urls(self, domain: str, limit: int = 10000) -> List[str]:
        """Extract all unique URLs for a domain from Wayback Machine."""
        print(f"[*] Extracting URLs for {domain}...")

        snapshots = self.query_cdx(domain, match_type='domain', limit=limit)
        urls = set()

        for snap in snapshots:
            url = snap.get('original', '')
            if url:
                urls.add(url)

        self.results['urls'] = sorted(list(urls))
        print(f"    Found {len(urls)} unique URLs")
        return self.results['urls']

    def find_parameters(self, urls: List[str]) -> Dict[str, List[str]]:
        """Extract parameters from archived URLs."""
        params_by_endpoint = {}

        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                params = parsed.query.split('&')

                if endpoint not in params_by_endpoint:
                    params_by_endpoint[endpoint] = set()

                for param in params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        params_by_endpoint[endpoint].add(param_name)
                        self.results['parameters'].add(param_name)

        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in params_by_endpoint.items()}

    def find_interesting_files(self, urls: List[str]) -> Dict[str, List[str]]:
        """Find interesting files in archived URLs."""
        interesting = {
            'js': [],
            'json': [],
            'xml': [],
            'config': [],
            'backup': [],
            'source': [],
            'api': []
        }

        patterns = {
            'js': [r'\.js$', r'\.js\?'],
            'json': [r'\.json$', r'\.json\?', r'/api/'],
            'xml': [r'\.xml$', r'\.xml\?', r'sitemap', r'\.rss'],
            'config': [r'config', r'settings', r'\.env', r'\.ini', r'\.conf'],
            'backup': [r'\.bak', r'\.backup', r'\.old', r'\.orig', r'~$', r'\.swp'],
            'source': [r'\.git', r'\.svn', r'\.hg', r'\.DS_Store', r'\.htaccess'],
            'api': [r'/api/', r'/v1/', r'/v2/', r'/graphql', r'/rest/']
        }

        for url in urls:
            url_lower = url.lower()
            for category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if re.search(pattern, url_lower):
                        if url not in interesting[category]:
                            interesting[category].append(url)
                        break

        self.results['files'] = interesting
        return interesting

    def find_removed_content(self, domain: str, current_urls: List[str] = None) -> List[str]:
        """
        Find URLs that existed in the past but may no longer exist.
        Useful for finding removed pages, old admin panels, etc.
        """
        archived_urls = self.extract_urls(domain)

        if current_urls:
            # Compare with current sitemap/crawl
            removed = [url for url in archived_urls if url not in current_urls]
            return removed

        return archived_urls

    def get_snapshot_content(self, url: str, timestamp: str = None) -> Optional[str]:
        """
        Get content from a specific Wayback snapshot.
        Note: This fetches from archive.org, not the target.
        """
        if timestamp:
            wayback_url = f"https://web.archive.org/web/{timestamp}/{url}"
        else:
            wayback_url = f"https://web.archive.org/web/{url}"

        try:
            response = requests.get(wayback_url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text
        except Exception:
            pass

        return None

    def check_availability(self, url: str) -> Dict[str, Any]:
        """Check if a URL is available in Wayback Machine."""
        try:
            response = requests.get(
                self.AVAILABILITY_API,
                params={'url': url},
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return {}

    def find_subdomains(self, domain: str) -> List[str]:
        """Extract subdomains from archived URLs."""
        urls = self.extract_urls(domain)
        subdomains = set()

        for url in urls:
            try:
                parsed = urlparse(url)
                host = parsed.netloc.lower()
                if host.endswith(domain):
                    subdomains.add(host)
            except Exception:
                pass

        return sorted(list(subdomains))

    def full_analysis(self, domain: str, limit: int = 10000) -> Dict[str, Any]:
        """Perform comprehensive Wayback Machine analysis."""
        print(f"\n{'='*60}")
        print(f"Wayback Machine Analysis: {domain}")
        print(f"{'='*60}\n")

        # Extract all URLs
        urls = self.extract_urls(domain, limit)

        # Find parameters
        print("\n[*] Extracting parameters from URLs...")
        params = self.find_parameters(urls)
        print(f"    Found {len(self.results['parameters'])} unique parameters")

        # Find interesting files
        print("\n[*] Finding interesting files...")
        files = self.find_interesting_files(urls)
        for category, file_list in files.items():
            if file_list:
                print(f"    {category}: {len(file_list)} files")

        # Extract subdomains
        print("\n[*] Extracting subdomains from URLs...")
        subdomains = self.find_subdomains(domain)
        self.results['subdomains'] = subdomains
        print(f"    Found {len(subdomains)} subdomains")

        # Metadata
        self.results['metadata'] = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'scan_type': 'passive',
            'total_urls': len(urls),
            'total_parameters': len(self.results['parameters']),
            'total_subdomains': len(subdomains)
        }

        # Convert set to list for JSON
        self.results['parameters'] = list(self.results['parameters'])
        self.results['endpoints'] = list(self.results['endpoints'])

        return self.results

    def save_results(self, output_file: str):
        """Save results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n[+] Results saved to {output_file}")

    def save_urls(self, output_file: str):
        """Save URLs to text file."""
        with open(output_file, 'w') as f:
            f.write('\n'.join(self.results['urls']))
        print(f"[+] URLs saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Wayback Machine URL Discovery (Passive)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wayback.py -d example.com
  python wayback.py -d example.com --urls-only -o urls.txt
  python wayback.py -d example.com --find-params
  python wayback.py -d example.com --find-files -o results.json
        """
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--urls-only", action="store_true",
                        help="Only output URLs")
    parser.add_argument("--find-params", action="store_true",
                        help="Extract parameters from URLs")
    parser.add_argument("--find-files", action="store_true",
                        help="Find interesting files (JS, JSON, etc.)")
    parser.add_argument("--limit", type=int, default=10000,
                        help="Maximum URLs to retrieve")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Request timeout")

    args = parser.parse_args()

    wayback = WaybackMachine(timeout=args.timeout)

    if args.urls_only:
        urls = wayback.extract_urls(args.domain, args.limit)
        print(f"\n[+] URLs found ({len(urls)}):")
        for url in urls[:100]:
            print(f"    {url}")
        if len(urls) > 100:
            print(f"    ... and {len(urls) - 100} more")

        if args.output:
            wayback.save_urls(args.output)
    else:
        results = wayback.full_analysis(args.domain, args.limit)

        # Print summary
        print(f"\n{'='*60}")
        print("Summary")
        print(f"{'='*60}")
        print(f"  Total URLs: {len(results['urls'])}")
        print(f"  Unique parameters: {len(results['parameters'])}")
        print(f"  Subdomains found: {len(results.get('subdomains', []))}")

        if results['files']:
            print(f"\n  Interesting Files:")
            for category, files in results['files'].items():
                if files:
                    print(f"    {category}: {len(files)}")

        if results['parameters']:
            print(f"\n  Sample Parameters:")
            for param in list(results['parameters'])[:20]:
                print(f"    - {param}")

        if results.get('subdomains'):
            print(f"\n  Subdomains:")
            for sub in results['subdomains'][:20]:
                print(f"    - {sub}")

        if args.output:
            wayback.save_results(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
