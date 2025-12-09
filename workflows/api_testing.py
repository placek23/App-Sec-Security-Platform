"""
API & Modern Application Testing Workflow

Phase 4 implementation for comprehensive API security testing:
- API Endpoint Discovery (Kiterunner)
- OpenAPI/Swagger Analysis
- GraphQL Security Testing
- WebSocket Security Testing
- JWT Token Testing
"""
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from wrappers.api.kiterunner import KiterunnerWrapper
from wrappers.api.openapi_analyzer import OpenAPIAnalyzer
from wrappers.api.graphql_tester import GraphQLTester
from wrappers.api.websocket_tester import WebSocketTester
from wrappers.api.jwt_tester import JWTTester
from utils.reporter import Reporter, ReportConfig


class APITestingWorkflow:
    """Comprehensive API security testing workflow."""

    def __init__(self, target: str, output_dir: str = None):
        """
        Initialize API testing workflow.

        Args:
            target: Target URL or domain
            output_dir: Output directory for results
        """
        self.target = target
        self.output_dir = Path(output_dir or f"./output/api_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize testers
        self.kiterunner = KiterunnerWrapper()
        self.openapi_analyzer = OpenAPIAnalyzer()
        self.graphql_tester = GraphQLTester()
        self.websocket_tester = WebSocketTester()
        self.jwt_tester = JWTTester()

        # Results storage
        self.all_findings = []
        self.results = {
            'api_discovery': [],
            'openapi_analysis': [],
            'graphql': [],
            'websocket': [],
            'jwt': []
        }

        # Discovered endpoints
        self.discovered_endpoints = []
        self.graphql_endpoints = []
        self.websocket_endpoints = []

    def run_api_discovery(self, headers: Dict = None, wordlist: str = None,
                          timeout: int = 600) -> Dict[str, Any]:
        """Run API endpoint discovery."""
        print("\n" + "="*60)
        print("API ENDPOINT DISCOVERY")
        print("="*60)

        result = self.kiterunner.run(
            target=self.target,
            headers=list(f"{k}: {v}" for k, v in (headers or {}).items()),
            wordlist=wordlist,
            include_fallback=True,
            timeout=timeout,
            output_file=str(self.output_dir / "api_discovery.json")
        )

        if result.get('success'):
            self.discovered_endpoints = result.get('results', [])

            # Identify GraphQL and WebSocket endpoints
            for endpoint in self.discovered_endpoints:
                url_lower = endpoint.url.lower()
                if 'graphql' in url_lower or 'graphiql' in url_lower:
                    self.graphql_endpoints.append(endpoint.url)
                if 'ws' in url_lower or 'socket' in url_lower or 'websocket' in url_lower:
                    self.websocket_endpoints.append(endpoint.url)

            print(f"[+] Discovery complete: {len(self.discovered_endpoints)} endpoints found")
            print(f"    GraphQL endpoints: {len(self.graphql_endpoints)}")
            print(f"    WebSocket endpoints: {len(self.websocket_endpoints)}")

            # Add findings
            interesting = [e for e in self.discovered_endpoints if e.interesting]
            for endpoint in interesting[:10]:
                self.all_findings.append({
                    'tool': 'kiterunner',
                    'target': self.target,
                    'finding_type': 'api_endpoint',
                    'title': f'API Endpoint Discovered: {endpoint.method} {endpoint.url}',
                    'description': endpoint.notes or 'Interesting API endpoint found',
                    'severity': 'info' if endpoint.status_code == 200 else 'low',
                    'url': endpoint.url,
                    'evidence': f'Status: {endpoint.status_code}, Length: {endpoint.content_length}'
                })

        self.results['api_discovery'] = self.discovered_endpoints
        return result

    def run_openapi_analysis(self, spec_file: str = None, spec_url: str = None,
                             headers: Dict = None, test_endpoints: bool = False) -> Dict[str, Any]:
        """Run OpenAPI/Swagger specification analysis."""
        print("\n" + "="*60)
        print("OPENAPI/SWAGGER ANALYSIS")
        print("="*60)

        result = self.openapi_analyzer.run(
            target=self.target,
            spec_file=spec_file,
            spec_url=spec_url,
            headers=headers,
            test_endpoints=test_endpoints,
            output_file=str(self.output_dir / "openapi_analysis.json")
        )

        if result.get('success'):
            issues = result.get('issues', [])
            print(f"[+] Analysis complete: {len(issues)} issues found")

            # Add findings
            for issue in issues:
                self.all_findings.append({
                    'tool': 'openapi_analyzer',
                    'target': self.target,
                    'finding_type': 'openapi_issue',
                    'title': issue.title,
                    'description': issue.description,
                    'severity': issue.severity,
                    'url': issue.endpoint if issue.endpoint else self.target,
                    'evidence': issue.evidence
                })

        self.results['openapi_analysis'] = result.get('issues', [])
        return result

    def run_graphql_testing(self, endpoints: List[str] = None, headers: Dict = None,
                           timeout: int = 30) -> Dict[str, Any]:
        """Run GraphQL security testing."""
        print("\n" + "="*60)
        print("GRAPHQL SECURITY TESTING")
        print("="*60)

        # Use discovered endpoints or provided list
        test_endpoints = endpoints or self.graphql_endpoints

        if not test_endpoints:
            # Try common GraphQL paths
            base_url = self.target.rstrip('/')
            common_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/gql']
            test_endpoints = [f"{base_url}{path}" for path in common_paths]

        all_graphql_findings = []

        for endpoint in test_endpoints:
            print(f"\n[*] Testing: {endpoint}")
            result = self.graphql_tester.run(
                target=endpoint,
                headers=headers,
                timeout=timeout,
                tests='all',
                output_file=str(self.output_dir / f"graphql_{urlparse(endpoint).path.replace('/', '_')}.json")
            )

            if result.get('success'):
                findings = result.get('results', [])
                vulnerable = [f for f in findings if f.vulnerable]

                if vulnerable:
                    print(f"    [+] Found {len(vulnerable)} vulnerabilities")
                    all_graphql_findings.extend(findings)

                    # Add to all findings
                    for finding in vulnerable:
                        self.all_findings.append({
                            'tool': 'graphql_tester',
                            'target': endpoint,
                            'finding_type': 'graphql',
                            'title': finding.title,
                            'description': finding.description,
                            'severity': finding.severity,
                            'url': endpoint,
                            'evidence': finding.evidence
                        })

        self.results['graphql'] = all_graphql_findings
        return {'success': True, 'findings': all_graphql_findings}

    def run_websocket_testing(self, endpoints: List[str] = None, headers: Dict = None,
                              timeout: int = 10) -> Dict[str, Any]:
        """Run WebSocket security testing."""
        print("\n" + "="*60)
        print("WEBSOCKET SECURITY TESTING")
        print("="*60)

        # Use discovered endpoints or provided list
        test_endpoints = endpoints or self.websocket_endpoints

        if not test_endpoints:
            # Try common WebSocket paths
            parsed = urlparse(self.target)
            ws_scheme = 'wss' if parsed.scheme == 'https' else 'ws'
            base = f"{ws_scheme}://{parsed.netloc}"
            common_paths = ['/ws', '/websocket', '/socket', '/socket.io', '/realtime']
            test_endpoints = [f"{base}{path}" for path in common_paths]

        all_ws_findings = []

        for endpoint in test_endpoints:
            print(f"\n[*] Testing: {endpoint}")
            result = self.websocket_tester.run(
                target=endpoint,
                headers=headers,
                timeout=timeout,
                tests='all',
                output_file=str(self.output_dir / f"websocket_{urlparse(endpoint).path.replace('/', '_')}.json")
            )

            if result.get('success'):
                findings = result.get('results', [])
                vulnerable = [f for f in findings if f.vulnerable]

                if vulnerable:
                    print(f"    [+] Found {len(vulnerable)} vulnerabilities")
                    all_ws_findings.extend(findings)

                    for finding in vulnerable:
                        self.all_findings.append({
                            'tool': 'websocket_tester',
                            'target': endpoint,
                            'finding_type': 'websocket',
                            'title': finding.title,
                            'description': finding.description,
                            'severity': finding.severity,
                            'url': endpoint,
                            'evidence': finding.evidence
                        })

        self.results['websocket'] = all_ws_findings
        return {'success': True, 'findings': all_ws_findings}

    def run_jwt_testing(self, token: str, test_url: str = None, headers: Dict = None,
                       wordlist: str = None) -> Dict[str, Any]:
        """Run JWT security testing."""
        print("\n" + "="*60)
        print("JWT SECURITY TESTING")
        print("="*60)

        result = self.jwt_tester.run(
            target=token,
            test_url=test_url or self.target,
            headers=headers,
            wordlist=wordlist,
            tests='all',
            output_file=str(self.output_dir / "jwt_analysis.json")
        )

        if result.get('success'):
            findings = result.get('results', [])
            vulnerable = [f for f in findings if f.vulnerable]

            print(f"[+] JWT analysis complete: {len(vulnerable)} vulnerabilities found")

            for finding in vulnerable:
                self.all_findings.append({
                    'tool': 'jwt_tester',
                    'target': self.target,
                    'finding_type': 'jwt',
                    'title': finding.title,
                    'description': finding.description,
                    'severity': finding.severity,
                    'url': self.target,
                    'evidence': finding.evidence
                })

        self.results['jwt'] = result.get('results', [])
        return result

    def run_full_scan(self, headers: Dict = None, jwt_token: str = None,
                      wordlist: str = None, skip_discovery: bool = False) -> Dict[str, Any]:
        """Run comprehensive API security scan."""
        print("\n" + "="*60)
        print("COMPREHENSIVE API SECURITY SCAN")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Output: {self.output_dir}")

        start_time = datetime.now()

        # Phase 1: API Discovery
        if not skip_discovery:
            self.run_api_discovery(headers=headers, wordlist=wordlist)

        # Phase 2: OpenAPI Analysis
        self.run_openapi_analysis(headers=headers, test_endpoints=True)

        # Phase 3: GraphQL Testing
        self.run_graphql_testing(headers=headers)

        # Phase 4: WebSocket Testing
        self.run_websocket_testing(headers=headers)

        # Phase 5: JWT Testing (if token provided)
        if jwt_token:
            self.run_jwt_testing(token=jwt_token, headers=headers, wordlist=wordlist)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Generate report
        self._generate_report()

        # Summary
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"Duration: {duration:.1f} seconds")
        print(f"\nFindings by type:")
        print(f"  API Discovery: {len(self.results['api_discovery'])}")
        print(f"  OpenAPI Issues: {len(self.results['openapi_analysis'])}")
        print(f"  GraphQL: {len([f for f in self.results['graphql'] if hasattr(f, 'vulnerable') and f.vulnerable])}")
        print(f"  WebSocket: {len([f for f in self.results['websocket'] if hasattr(f, 'vulnerable') and f.vulnerable])}")
        print(f"  JWT: {len([f for f in self.results['jwt'] if hasattr(f, 'vulnerable') and f.vulnerable])}")
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
            title="API Security Assessment Report",
            target=self.target,
            tester="AppSec Bounty Platform - Phase 4"
        )

        reporter = Reporter(config)
        reporter.add_findings(self.all_findings)

        # Generate HTML report
        report_path = self.output_dir / "api_security_report.html"
        reporter.generate_html(str(report_path))

        # Generate JSON report
        json_path = self.output_dir / "api_security_report.json"
        reporter.generate_json(str(json_path))

        print(f"\n[+] Reports generated:")
        print(f"    HTML: {report_path}")
        print(f"    JSON: {json_path}")


def main():
    parser = argparse.ArgumentParser(
        description="API Security Testing Workflow - Phase 4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python api_testing.py -t https://api.example.com
  python api_testing.py -t https://example.com --test discovery,openapi,graphql
  python api_testing.py -t https://api.example.com --jwt "eyJhbG..." -H "Cookie: session=xxx"
  python api_testing.py -t https://example.com --spec swagger.json --test openapi
  python api_testing.py -t https://api.example.com -o ./results --wordlist /path/to/wordlist
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("--jwt", dest="jwt_token", help="JWT token to analyze")
    parser.add_argument("--spec", dest="spec_file", help="OpenAPI/Swagger spec file")
    parser.add_argument("--wordlist", help="Wordlist for discovery and JWT cracking")
    parser.add_argument("--graphql-endpoints", dest="graphql_endpoints",
                       help="Comma-separated GraphQL endpoints")
    parser.add_argument("--ws-endpoints", dest="ws_endpoints",
                       help="Comma-separated WebSocket endpoints")
    parser.add_argument("--test",
                       help="Comma-separated tests: discovery,openapi,graphql,websocket,jwt,all (default: all)")
    parser.add_argument("--skip-discovery", action="store_true",
                       help="Skip API discovery phase")

    args = parser.parse_args()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()

    workflow = APITestingWorkflow(
        target=args.target,
        output_dir=args.output
    )

    # Determine which tests to run
    if args.test:
        tests = [t.strip().lower() for t in args.test.split(',')]
    else:
        tests = ['all']

    if 'all' in tests:
        # Run full scan
        workflow.run_full_scan(
            headers=headers,
            jwt_token=args.jwt_token,
            wordlist=args.wordlist,
            skip_discovery=args.skip_discovery
        )
    else:
        # Run selected tests
        if 'discovery' in tests:
            workflow.run_api_discovery(headers=headers, wordlist=args.wordlist)

        if 'openapi' in tests:
            workflow.run_openapi_analysis(
                spec_file=args.spec_file,
                headers=headers,
                test_endpoints=True
            )

        if 'graphql' in tests:
            graphql_eps = args.graphql_endpoints.split(',') if args.graphql_endpoints else None
            workflow.run_graphql_testing(endpoints=graphql_eps, headers=headers)

        if 'websocket' in tests:
            ws_eps = args.ws_endpoints.split(',') if args.ws_endpoints else None
            workflow.run_websocket_testing(endpoints=ws_eps, headers=headers)

        if 'jwt' in tests and args.jwt_token:
            workflow.run_jwt_testing(
                token=args.jwt_token,
                headers=headers,
                wordlist=args.wordlist
            )

        # Generate report for partial scan
        workflow._generate_report()

        print(f"\n[+] Results saved to: {workflow.output_dir}")

    return 0


if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
