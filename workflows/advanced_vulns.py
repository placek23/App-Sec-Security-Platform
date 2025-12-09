"""
Advanced Vulnerability Testing Workflow

Phase 3.5 implementation for testing advanced web vulnerabilities:
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- HTTP Request Smuggling
- Race Conditions
- CORS Misconfigurations
- File Upload Bypass
"""
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.advanced.ssrf_tester import SSRFTester
from wrappers.advanced.xxe_injector import XXEInjector
from wrappers.advanced.http_smuggler import HTTPSmuggler
from wrappers.advanced.race_condition import RaceConditionTester
from wrappers.advanced.cors_tester import CORSTester
from wrappers.advanced.file_upload_bypass import FileUploadBypass
from utils.reporter import Reporter, ReportConfig


class AdvancedVulnWorkflow:
    """Advanced vulnerability testing workflow."""

    def __init__(self, target: str, output_dir: str = None, callback_url: str = None):
        """
        Initialize advanced vulnerability workflow.

        Args:
            target: Target URL
            output_dir: Output directory for results
            callback_url: OOB callback URL for blind vulnerabilities
        """
        self.target = target
        self.callback_url = callback_url
        self.output_dir = Path(output_dir or f"./output/advanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize testers
        self.ssrf_tester = SSRFTester()
        self.xxe_injector = XXEInjector()
        self.http_smuggler = HTTPSmuggler()
        self.race_tester = RaceConditionTester()
        self.cors_tester = CORSTester()
        self.upload_bypass = FileUploadBypass()

        # Results storage
        self.all_findings = []
        self.results = {
            'ssrf': [],
            'xxe': [],
            'smuggling': [],
            'race_condition': [],
            'cors': [],
            'file_upload': []
        }

    def run_ssrf_test(self, param: str = 'url', method: str = 'GET',
                      headers: Dict = None, timeout: int = 10) -> List[Any]:
        """Run SSRF tests."""
        print("\n" + "="*60)
        print("SSRF TESTING")
        print("="*60)

        result = self.ssrf_tester.run(
            target=self.target,
            param=param,
            method=method,
            callback_url=self.callback_url,
            headers=headers,
            timeout=timeout,
            output_file=str(self.output_dir / "ssrf_results.json")
        )

        findings = result.get('results', [])
        vulnerable = [f for f in findings if f.potential_vuln]

        print(f"[+] SSRF testing complete")
        print(f"    Total tests: {len(findings)}")
        print(f"    Potential vulnerabilities: {len(vulnerable)}")

        # Add to findings
        for finding in vulnerable:
            self.all_findings.append({
                'tool': 'ssrf_tester',
                'target': self.target,
                'finding_type': 'ssrf',
                'title': f'Potential SSRF via {param}',
                'description': f'SSRF detected using payload type: {finding.payload_type}',
                'severity': 'high' if finding.cloud_provider else 'medium',
                'url': self.target,
                'parameter': param,
                'evidence': finding.evidence
            })

        self.results['ssrf'] = findings
        return findings

    def run_xxe_test(self, headers: Dict = None, timeout: int = 15) -> List[Any]:
        """Run XXE tests."""
        print("\n" + "="*60)
        print("XXE TESTING")
        print("="*60)

        result = self.xxe_injector.run(
            target=self.target,
            callback_url=self.callback_url,
            headers=headers,
            timeout=timeout,
            output_file=str(self.output_dir / "xxe_results.json")
        )

        findings = result.get('results', [])
        vulnerable = [f for f in findings if f.potential_vuln]

        print(f"[+] XXE testing complete")
        print(f"    Total tests: {len(findings)}")
        print(f"    Potential vulnerabilities: {len(vulnerable)}")

        # Add to findings
        for finding in vulnerable:
            self.all_findings.append({
                'tool': 'xxe_injector',
                'target': self.target,
                'finding_type': 'xxe',
                'title': f'Potential XXE ({finding.payload_type})',
                'description': 'XML External Entity injection detected',
                'severity': 'critical',
                'url': self.target,
                'evidence': finding.evidence
            })

        self.results['xxe'] = findings
        return findings

    def run_smuggling_test(self, timeout: int = 10) -> List[Any]:
        """Run HTTP smuggling tests."""
        print("\n" + "="*60)
        print("HTTP SMUGGLING TESTING")
        print("="*60)

        result = self.http_smuggler.run(
            target=self.target,
            timeout=timeout,
            output_file=str(self.output_dir / "smuggling_results.json")
        )

        findings = result.get('results', [])
        vulnerable = [f for f in findings if f.potential_vuln]

        print(f"[+] HTTP smuggling testing complete")
        print(f"    Total tests: {len(findings)}")
        print(f"    Potential vulnerabilities: {len(vulnerable)}")

        # Add to findings
        for finding in vulnerable:
            self.all_findings.append({
                'tool': 'http_smuggler',
                'target': self.target,
                'finding_type': 'http_smuggling',
                'title': f'Potential HTTP Smuggling ({finding.technique})',
                'description': f'HTTP request smuggling detected using {finding.variant}',
                'severity': 'high',
                'url': self.target,
                'evidence': finding.evidence
            })

        self.results['smuggling'] = findings
        return findings

    def run_race_test(self, method: str = 'POST', data: Dict = None,
                      headers: Dict = None, parallel_requests: int = 10) -> List[Any]:
        """Run race condition tests."""
        print("\n" + "="*60)
        print("RACE CONDITION TESTING")
        print("="*60)

        result = self.race_tester.run(
            target=self.target,
            method=method,
            data=data,
            headers=headers,
            parallel_requests=parallel_requests,
            test_type='all',
            output_file=str(self.output_dir / "race_results.json")
        )

        findings = result.get('results', [])
        vulnerable = [f for f in findings if f.potential_vuln]

        print(f"[+] Race condition testing complete")
        print(f"    Total tests: {len(findings)}")
        print(f"    Potential vulnerabilities: {len(vulnerable)}")

        # Add to findings
        for finding in vulnerable:
            self.all_findings.append({
                'tool': 'race_condition',
                'target': self.target,
                'finding_type': 'race_condition',
                'title': f'Potential Race Condition ({finding.test_type})',
                'description': f'Race condition detected: {finding.successful_requests}/{finding.total_requests} succeeded',
                'severity': 'medium',
                'url': self.target,
                'evidence': finding.evidence
            })

        self.results['race_condition'] = findings
        return findings

    def run_cors_test(self, headers: Dict = None, timeout: int = 10) -> List[Any]:
        """Run CORS misconfiguration tests."""
        print("\n" + "="*60)
        print("CORS MISCONFIGURATION TESTING")
        print("="*60)

        result = self.cors_tester.run(
            target=self.target,
            headers=headers,
            timeout=timeout,
            output_file=str(self.output_dir / "cors_results.json")
        )

        findings = result.get('results', [])
        vulnerable = [f for f in findings if f.vulnerability_level not in ['none', 'info']]

        print(f"[+] CORS testing complete")
        print(f"    Total tests: {len(findings)}")
        print(f"    Potential vulnerabilities: {len(vulnerable)}")

        # Add to findings
        for finding in vulnerable:
            severity_map = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low'}
            self.all_findings.append({
                'tool': 'cors_tester',
                'target': self.target,
                'finding_type': 'cors',
                'title': f'CORS Misconfiguration ({finding.origin_type})',
                'description': f'Origin {finding.origin_tested} is reflected',
                'severity': severity_map.get(finding.vulnerability_level, 'info'),
                'url': self.target,
                'evidence': finding.evidence
            })

        self.results['cors'] = findings
        return findings

    def run_upload_test(self, file_param: str = 'file', additional_data: Dict = None,
                       headers: Dict = None, timeout: int = 15) -> List[Any]:
        """Run file upload bypass tests."""
        print("\n" + "="*60)
        print("FILE UPLOAD BYPASS TESTING")
        print("="*60)

        result = self.upload_bypass.run(
            target=self.target,
            file_param=file_param,
            additional_data=additional_data,
            headers=headers,
            timeout=timeout,
            output_file=str(self.output_dir / "upload_results.json")
        )

        findings = result.get('results', [])
        vulnerable = [f for f in findings if f.upload_success]
        rce = [f for f in findings if f.potential_rce]

        print(f"[+] File upload testing complete")
        print(f"    Total tests: {len(findings)}")
        print(f"    Successful uploads: {len(vulnerable)}")
        print(f"    Potential RCE: {len(rce)}")

        # Add to findings
        for finding in rce:
            self.all_findings.append({
                'tool': 'file_upload_bypass',
                'target': self.target,
                'finding_type': 'file_upload',
                'title': f'File Upload Bypass ({finding.technique})',
                'description': f'Uploaded {finding.filename} as {finding.content_type}',
                'severity': 'critical' if finding.potential_rce else 'high',
                'url': self.target,
                'evidence': finding.evidence
            })

        self.results['file_upload'] = findings
        return findings

    def run_full_scan(self, ssrf_param: str = 'url', upload_param: str = 'file',
                      headers: Dict = None, parallel_requests: int = 10) -> Dict[str, Any]:
        """Run all advanced vulnerability tests."""
        print("\n" + "="*60)
        print("ADVANCED VULNERABILITY SCAN")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Output: {self.output_dir}")

        start_time = datetime.now()

        # Run all tests
        self.run_ssrf_test(param=ssrf_param, headers=headers)
        self.run_xxe_test(headers=headers)
        self.run_smuggling_test()
        self.run_race_test(headers=headers, parallel_requests=parallel_requests)
        self.run_cors_test(headers=headers)
        self.run_upload_test(file_param=upload_param, headers=headers)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Generate report
        self._generate_report()

        # Summary
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"Duration: {duration:.1f} seconds")
        print(f"\nVulnerabilities by type:")
        print(f"  SSRF: {len([f for f in self.results['ssrf'] if hasattr(f, 'potential_vuln') and f.potential_vuln])}")
        print(f"  XXE: {len([f for f in self.results['xxe'] if hasattr(f, 'potential_vuln') and f.potential_vuln])}")
        print(f"  HTTP Smuggling: {len([f for f in self.results['smuggling'] if hasattr(f, 'potential_vuln') and f.potential_vuln])}")
        print(f"  Race Condition: {len([f for f in self.results['race_condition'] if hasattr(f, 'potential_vuln') and f.potential_vuln])}")
        print(f"  CORS: {len([f for f in self.results['cors'] if hasattr(f, 'vulnerability_level') and f.vulnerability_level not in ['none', 'info']])}")
        print(f"  File Upload: {len([f for f in self.results['file_upload'] if hasattr(f, 'potential_rce') and f.potential_rce])}")
        print(f"\nTotal findings: {len(self.all_findings)}")
        print(f"Output directory: {self.output_dir}")

        return {
            'target': self.target,
            'duration': duration,
            'results': self.results,
            'findings': self.all_findings,
            'output_dir': str(self.output_dir)
        }

    def _generate_report(self):
        """Generate scan report."""
        config = ReportConfig(
            title="Advanced Vulnerability Scan Report",
            target=self.target,
            tester="AppSec Bounty Platform - Phase 3.5"
        )

        reporter = Reporter(config)
        reporter.add_findings(self.all_findings)

        # Generate HTML report
        report_path = self.output_dir / "advanced_vulns_report.html"
        reporter.generate_html(str(report_path))

        # Generate JSON report
        json_path = self.output_dir / "advanced_vulns_report.json"
        reporter.generate_json(str(json_path))


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Vulnerability Scanner - Phase 3.5",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_vulns.py -t "https://example.com"
  python advanced_vulns.py -t "https://example.com/api" --ssrf-param url --callback http://your-callback.com
  python advanced_vulns.py -t "https://example.com/upload" --upload-param file --test ssrf,xxe,upload
  python advanced_vulns.py -t "https://example.com" --test cors,smuggling -o ./results
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--callback", help="OOB callback URL for blind vulnerabilities")
    parser.add_argument("--ssrf-param", default="url", help="Parameter for SSRF testing (default: url)")
    parser.add_argument("--upload-param", default="file", help="Parameter for file upload (default: file)")
    parser.add_argument("--parallel", type=int, default=10, help="Parallel requests for race condition (default: 10)")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("--test", help="Comma-separated list of tests to run (ssrf,xxe,smuggling,race,cors,upload)")

    args = parser.parse_args()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    workflow = AdvancedVulnWorkflow(
        target=args.target,
        output_dir=args.output,
        callback_url=args.callback
    )

    # Run specific tests or all
    if args.test:
        tests = [t.strip().lower() for t in args.test.split(',')]

        if 'ssrf' in tests:
            workflow.run_ssrf_test(param=args.ssrf_param, headers=headers)
        if 'xxe' in tests:
            workflow.run_xxe_test(headers=headers)
        if 'smuggling' in tests:
            workflow.run_smuggling_test()
        if 'race' in tests:
            workflow.run_race_test(headers=headers, parallel_requests=args.parallel)
        if 'cors' in tests:
            workflow.run_cors_test(headers=headers)
        if 'upload' in tests:
            workflow.run_upload_test(file_param=args.upload_param, headers=headers)

        # Generate report for partial scan
        workflow._generate_report()

        print(f"\n[+] Results saved to: {workflow.output_dir}")
    else:
        # Run full scan
        workflow.run_full_scan(
            ssrf_param=args.ssrf_param,
            upload_param=args.upload_param,
            headers=headers if headers else None,
            parallel_requests=args.parallel
        )

    return 0


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
