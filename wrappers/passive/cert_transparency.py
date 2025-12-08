#!/usr/bin/env python3
"""
Certificate Transparency - Passive certificate analysis
Queries public CT logs for certificate information
"""
import sys
import json
import argparse
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import requests
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class CertTransparency:
    """
    Certificate Transparency log analyzer.

    Completely passive - queries public CT logs and certificate databases.
    No direct interaction with target servers.

    Features:
    - Subdomain discovery via CT logs
    - Certificate history analysis
    - Certificate details extraction
    - Issuer analysis
    - Expiration monitoring
    """

    CT_SOURCES = {
        'crtsh': 'https://crt.sh',
        'censys': 'https://search.censys.io',  # Requires API key
        'certspotter': 'https://api.certspotter.com/v1/issuances',
    }

    def __init__(self):
        self.results = {
            'certificates': [],
            'subdomains': [],
            'issuers': {},
            'timeline': [],
            'metadata': {}
        }

    def query_crtsh(self, domain: str, include_expired: bool = True,
                    wildcard: bool = True) -> List[Dict[str, Any]]:
        """
        Query crt.sh for certificates.
        Returns certificate metadata from CT logs.
        """
        certificates = []
        query = f"%.{domain}" if wildcard else domain
        url = f"https://crt.sh/?q={quote(query)}&output=json"

        if not include_expired:
            url += "&exclude=expired"

        try:
            response = requests.get(url, timeout=60)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    certificates.append({
                        'id': cert.get('id'),
                        'issuer': cert.get('issuer_name'),
                        'common_name': cert.get('common_name'),
                        'name_value': cert.get('name_value'),
                        'not_before': cert.get('not_before'),
                        'not_after': cert.get('not_after'),
                        'serial_number': cert.get('serial_number'),
                    })
        except requests.exceptions.JSONDecodeError:
            print(f"  [!] crt.sh returned non-JSON response")
        except Exception as e:
            print(f"  [!] crt.sh error: {e}")

        return certificates

    def query_certspotter(self, domain: str) -> List[Dict[str, Any]]:
        """
        Query Cert Spotter API for certificates.
        Free tier available with rate limits.
        """
        certificates = []
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"

        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    certificates.append({
                        'id': cert.get('id'),
                        'dns_names': cert.get('dns_names', []),
                        'issuer': cert.get('issuer', {}).get('name'),
                        'not_before': cert.get('not_before'),
                        'not_after': cert.get('not_after'),
                        'pubkey_sha256': cert.get('pubkey_sha256'),
                    })
            elif response.status_code == 429:
                print("  [!] CertSpotter rate limit reached")
        except Exception as e:
            print(f"  [!] CertSpotter error: {e}")

        return certificates

    def extract_subdomains(self, certificates: List[Dict]) -> List[str]:
        """Extract unique subdomains from certificate data."""
        subdomains = set()

        for cert in certificates:
            # From name_value (crt.sh)
            name_value = cert.get('name_value', '')
            if name_value:
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    if name.startswith('*.'):
                        name = name[2:]
                    if name and not name.startswith('*'):
                        subdomains.add(name)

            # From common_name
            cn = cert.get('common_name', '')
            if cn:
                cn = cn.strip().lower()
                if cn.startswith('*.'):
                    cn = cn[2:]
                if cn and not cn.startswith('*'):
                    subdomains.add(cn)

            # From dns_names (CertSpotter)
            dns_names = cert.get('dns_names', [])
            for name in dns_names:
                name = name.strip().lower()
                if name.startswith('*.'):
                    name = name[2:]
                if name and not name.startswith('*'):
                    subdomains.add(name)

        return sorted(list(subdomains))

    def analyze_issuers(self, certificates: List[Dict]) -> Dict[str, int]:
        """Analyze certificate issuers."""
        issuers = {}
        for cert in certificates:
            issuer = cert.get('issuer', 'Unknown')
            if issuer:
                # Extract organization from issuer string
                org_match = re.search(r'O=([^,]+)', str(issuer))
                if org_match:
                    org = org_match.group(1)
                else:
                    org = str(issuer)[:50]
                issuers[org] = issuers.get(org, 0) + 1
        return dict(sorted(issuers.items(), key=lambda x: x[1], reverse=True))

    def build_timeline(self, certificates: List[Dict]) -> List[Dict]:
        """Build certificate issuance timeline."""
        timeline = []
        for cert in certificates:
            not_before = cert.get('not_before')
            if not_before:
                timeline.append({
                    'date': not_before,
                    'event': 'issued',
                    'common_name': cert.get('common_name', 'Unknown'),
                    'issuer': cert.get('issuer', 'Unknown')[:50]
                })
        return sorted(timeline, key=lambda x: x['date'], reverse=True)[:100]

    def find_expiring_soon(self, certificates: List[Dict], days: int = 30) -> List[Dict]:
        """Find certificates expiring within specified days."""
        expiring = []
        now = datetime.now()

        for cert in certificates:
            not_after = cert.get('not_after')
            if not_after:
                try:
                    # Parse various date formats
                    for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                        try:
                            exp_date = datetime.strptime(not_after[:19], fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        continue

                    days_until = (exp_date - now).days
                    if 0 < days_until <= days:
                        expiring.append({
                            'common_name': cert.get('common_name'),
                            'expires': not_after,
                            'days_until_expiry': days_until
                        })
                except Exception:
                    pass

        return sorted(expiring, key=lambda x: x['days_until_expiry'])

    def get_certificate_details(self, cert_id: int) -> Optional[Dict]:
        """Get detailed certificate information from crt.sh."""
        url = f"https://crt.sh/?id={cert_id}&opt=cablint,zlint,x509lint"

        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                return {'id': cert_id, 'details_url': url}
        except Exception:
            pass
        return None

    def full_analysis(self, domain: str, include_expired: bool = False) -> Dict[str, Any]:
        """Perform comprehensive CT log analysis."""
        print(f"\n{'='*60}")
        print(f"Certificate Transparency Analysis: {domain}")
        print(f"{'='*60}\n")

        # Query CT logs
        print("[*] Querying crt.sh...")
        crtsh_certs = self.query_crtsh(domain, include_expired)
        print(f"    Found {len(crtsh_certs)} certificates")

        print("[*] Querying CertSpotter...")
        certspotter_certs = self.query_certspotter(domain)
        print(f"    Found {len(certspotter_certs)} certificates")

        # Combine results
        all_certs = crtsh_certs + certspotter_certs
        self.results['certificates'] = all_certs

        # Extract subdomains
        print("\n[*] Extracting subdomains from certificates...")
        subdomains = self.extract_subdomains(all_certs)
        self.results['subdomains'] = subdomains
        print(f"    Found {len(subdomains)} unique subdomains")

        # Analyze issuers
        print("\n[*] Analyzing certificate issuers...")
        issuers = self.analyze_issuers(all_certs)
        self.results['issuers'] = issuers

        # Build timeline
        timeline = self.build_timeline(all_certs)
        self.results['timeline'] = timeline

        # Find expiring certificates
        expiring = self.find_expiring_soon(crtsh_certs)
        self.results['expiring_soon'] = expiring

        # Metadata
        self.results['metadata'] = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'scan_type': 'passive',
            'total_certificates': len(all_certs),
            'total_subdomains': len(subdomains),
            'include_expired': include_expired
        }

        return self.results

    def save_results(self, output_file: str):
        """Save results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n[+] Results saved to {output_file}")

    def save_subdomains(self, output_file: str):
        """Save subdomains to text file."""
        with open(output_file, 'w') as f:
            f.write('\n'.join(self.results['subdomains']))
        print(f"[+] Subdomains saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Certificate Transparency Log Analyzer (Passive)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cert_transparency.py -d example.com
  python cert_transparency.py -d example.com --subdomains-only -o subs.txt
  python cert_transparency.py -d example.com --include-expired -o results.json
        """
    )

    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--subdomains-only", action="store_true",
                        help="Only output subdomains")
    parser.add_argument("--include-expired", action="store_true",
                        help="Include expired certificates")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")

    args = parser.parse_args()

    ct = CertTransparency()
    results = ct.full_analysis(args.domain, args.include_expired)

    if args.subdomains_only:
        print(f"\n[+] Subdomains found ({len(results['subdomains'])}):")
        for sub in results['subdomains'][:100]:
            print(f"    {sub}")
        if len(results['subdomains']) > 100:
            print(f"    ... and {len(results['subdomains']) - 100} more")

        if args.output:
            ct.save_subdomains(args.output)
    else:
        # Print summary
        print(f"\n{'='*60}")
        print("Summary")
        print(f"{'='*60}")
        print(f"  Total certificates: {len(results['certificates'])}")
        print(f"  Unique subdomains: {len(results['subdomains'])}")
        print(f"  Expiring soon: {len(results.get('expiring_soon', []))}")

        print(f"\n  Top Certificate Issuers:")
        for issuer, count in list(results['issuers'].items())[:5]:
            print(f"    {count:4d} - {issuer[:50]}")

        if results.get('expiring_soon'):
            print(f"\n  Certificates Expiring Soon:")
            for cert in results['expiring_soon'][:5]:
                print(f"    {cert['days_until_expiry']:3d} days - {cert['common_name']}")

        if args.output:
            ct.save_results(args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
