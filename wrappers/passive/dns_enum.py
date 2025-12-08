#!/usr/bin/env python3
"""
DNS Enumeration - Passive DNS reconnaissance
Performs DNS lookups and subdomain enumeration via public sources
"""
import sys
import socket
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import dns.resolver
import dns.reversename
import requests

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class DNSEnumerator:
    """
    Passive DNS enumeration tool.

    Performs:
    - DNS record lookups (A, AAAA, MX, NS, TXT, CNAME, SOA)
    - Reverse DNS lookups
    - Subdomain enumeration via public APIs (no direct target interaction)
    """

    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV']

    # Public APIs for passive subdomain enumeration
    SUBDOMAIN_APIS = {
        'crtsh': 'https://crt.sh/?q=%.{domain}&output=json',
        'hackertarget': 'https://api.hackertarget.com/hostsearch/?q={domain}',
        'rapiddns': 'https://rapiddns.io/subdomain/{domain}?full=1',
        'alienvault': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
    }

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.results = {
            'dns_records': {},
            'subdomains': [],
            'reverse_dns': {},
            'metadata': {}
        }

    def lookup_records(self, domain: str, record_types: List[str] = None) -> Dict[str, Any]:
        """
        Perform DNS lookups for specified record types.
        This queries public DNS servers, not the target directly.
        """
        record_types = record_types or self.RECORD_TYPES
        records = {}

        for rtype in record_types:
            try:
                answers = self.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                records[rtype] = ['NXDOMAIN']
                break
            except dns.resolver.NoNameservers:
                records[rtype] = ['NO_NAMESERVERS']
            except Exception as e:
                records[rtype] = [f'ERROR: {str(e)}']

        self.results['dns_records'][domain] = records
        return records

    def reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup on an IP address."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')
            hostname = str(answers[0]).rstrip('.')
            self.results['reverse_dns'][ip] = hostname
            return hostname
        except Exception:
            return None

    def enumerate_subdomains_crtsh(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using Certificate Transparency logs (crt.sh).
        Completely passive - queries public CT logs.
        """
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle wildcard and multi-line entries
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.startswith('*.'):
                            sub = sub[2:]
                        if sub.endswith(domain) and sub not in subdomains:
                            subdomains.add(sub)
        except Exception as e:
            print(f"  [!] crt.sh error: {e}")

        return list(subdomains)

    def enumerate_subdomains_hackertarget(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using HackerTarget API.
        Passive - uses their cached data.
        """
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"

        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200 and 'error' not in response.text.lower():
                for line in response.text.strip().split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(domain):
                            subdomains.add(subdomain)
        except Exception as e:
            print(f"  [!] HackerTarget error: {e}")

        return list(subdomains)

    def enumerate_subdomains_alienvault(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using AlienVault OTX.
        Passive - uses threat intelligence data.
        """
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '').lower()
                    if hostname.endswith(domain):
                        subdomains.add(hostname)
        except Exception as e:
            print(f"  [!] AlienVault error: {e}")

        return list(subdomains)

    def enumerate_subdomains(self, domain: str, sources: List[str] = None) -> List[str]:
        """
        Enumerate subdomains from multiple passive sources.
        """
        sources = sources or ['crtsh', 'hackertarget', 'alienvault']
        all_subdomains = set()

        print(f"[*] Enumerating subdomains for {domain} (passive)")

        if 'crtsh' in sources:
            print("  [*] Querying crt.sh (Certificate Transparency)...")
            subs = self.enumerate_subdomains_crtsh(domain)
            print(f"      Found {len(subs)} subdomains")
            all_subdomains.update(subs)

        if 'hackertarget' in sources:
            print("  [*] Querying HackerTarget...")
            subs = self.enumerate_subdomains_hackertarget(domain)
            print(f"      Found {len(subs)} subdomains")
            all_subdomains.update(subs)

        if 'alienvault' in sources:
            print("  [*] Querying AlienVault OTX...")
            subs = self.enumerate_subdomains_alienvault(domain)
            print(f"      Found {len(subs)} subdomains")
            all_subdomains.update(subs)

        self.results['subdomains'] = sorted(list(all_subdomains))
        return self.results['subdomains']

    def get_nameservers(self, domain: str) -> List[str]:
        """Get authoritative nameservers for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(ns).rstrip('.') for ns in answers]
        except Exception:
            return []

    def get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX records with priorities."""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [{'priority': mx.preference, 'host': str(mx.exchange).rstrip('.')}
                    for mx in answers]
        except Exception:
            return []

    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records (often contain SPF, DKIM, DMARC info)."""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(txt).strip('"') for txt in answers]
        except Exception:
            return []

    def analyze_security_records(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS records for security configurations."""
        security = {
            'spf': None,
            'dmarc': None,
            'dkim_selector_found': False,
            'dnssec': False,
            'caa': []
        }

        # Check TXT records for SPF
        txt_records = self.get_txt_records(domain)
        for txt in txt_records:
            if txt.startswith('v=spf1'):
                security['spf'] = txt

        # Check DMARC
        try:
            dmarc_answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for txt in dmarc_answers:
                txt_str = str(txt).strip('"')
                if txt_str.startswith('v=DMARC1'):
                    security['dmarc'] = txt_str
        except Exception:
            pass

        # Check CAA records
        try:
            caa_answers = self.resolver.resolve(domain, 'CAA')
            security['caa'] = [str(caa) for caa in caa_answers]
        except Exception:
            pass

        return security

    def full_enumeration(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive passive DNS enumeration."""
        print(f"\n{'='*60}")
        print(f"Passive DNS Enumeration: {domain}")
        print(f"{'='*60}\n")

        # Basic DNS records
        print("[*] Looking up DNS records...")
        self.lookup_records(domain)

        # Subdomain enumeration
        print("\n[*] Enumerating subdomains from passive sources...")
        subdomains = self.enumerate_subdomains(domain)

        # Security analysis
        print("\n[*] Analyzing security DNS records...")
        security = self.analyze_security_records(domain)
        self.results['security'] = security

        # Get IPs and do reverse lookups
        print("\n[*] Performing reverse DNS lookups...")
        a_records = self.results['dns_records'].get(domain, {}).get('A', [])
        for ip in a_records:
            if not ip.startswith('ERROR') and ip != 'NXDOMAIN':
                hostname = self.reverse_lookup(ip)
                if hostname:
                    print(f"    {ip} -> {hostname}")

        # Metadata
        self.results['metadata'] = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'scan_type': 'passive',
            'total_subdomains': len(subdomains)
        }

        return self.results

    def save_results(self, output_file: str):
        """Save results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[+] Results saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Passive DNS Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dns_enum.py -d example.com
  python dns_enum.py -d example.com --subdomains-only
  python dns_enum.py -d example.com -o results.json
  python dns_enum.py -d example.com --records A AAAA MX
        """
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--records", nargs="+", help="Record types to query")
    parser.add_argument("--subdomains-only", action="store_true",
                        help="Only enumerate subdomains")
    parser.add_argument("--sources", nargs="+",
                        choices=['crtsh', 'hackertarget', 'alienvault'],
                        default=['crtsh', 'hackertarget', 'alienvault'],
                        help="Subdomain enumeration sources")
    parser.add_argument("--timeout", type=int, default=5,
                        help="DNS query timeout")

    args = parser.parse_args()

    enumerator = DNSEnumerator(timeout=args.timeout)

    if args.subdomains_only:
        subdomains = enumerator.enumerate_subdomains(args.domain, args.sources)
        print(f"\n[+] Found {len(subdomains)} unique subdomains:")
        for sub in sorted(subdomains)[:50]:
            print(f"    {sub}")
        if len(subdomains) > 50:
            print(f"    ... and {len(subdomains) - 50} more")
    else:
        results = enumerator.full_enumeration(args.domain)

        # Print summary
        print(f"\n{'='*60}")
        print("Summary")
        print(f"{'='*60}")
        print(f"  Subdomains found: {len(results.get('subdomains', []))}")
        print(f"  DNS Records: {list(results.get('dns_records', {}).get(args.domain, {}).keys())}")

        security = results.get('security', {})
        print(f"\n  Security Records:")
        print(f"    SPF: {'✓' if security.get('spf') else '✗'}")
        print(f"    DMARC: {'✓' if security.get('dmarc') else '✗'}")
        print(f"    CAA: {'✓' if security.get('caa') else '✗'}")

    if args.output:
        enumerator.save_results(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
