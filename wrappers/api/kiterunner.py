"""
Kiterunner Wrapper - API Endpoint Discovery

Kiterunner is a contextual content discovery tool for API endpoints.
It uses OpenAPI/Swagger specs and wordlists to discover API routes.

Features:
- API endpoint brute-forcing with context-aware requests
- OpenAPI/Swagger specification replay
- Support for Kitebuilder routes
- Multiple authentication methods
"""
import sys
import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import APITool
from utils.output_parser import Finding, Severity, Endpoint


@dataclass
class APIEndpointFinding:
    """Represents a discovered API endpoint"""
    url: str
    method: str
    status_code: int
    content_length: int
    content_type: str = ""
    response_time: float = 0.0
    matched_route: str = ""
    source: str = "kiterunner"
    parameters: List[str] = field(default_factory=list)
    interesting: bool = False
    notes: str = ""


class KiterunnerWrapper(APITool):
    """Kiterunner wrapper for API endpoint discovery."""

    # Common API paths for fallback discovery
    COMMON_API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/graphql", "/graphiql",
        "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
        "/openapi", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api/docs", "/docs",
        "/health", "/healthz", "/health/live", "/health/ready",
        "/status", "/info", "/version", "/ping",
        "/metrics", "/prometheus",
        "/admin", "/admin/api", "/management",
        "/actuator", "/actuator/health", "/actuator/info",
        "/.well-known", "/.well-known/openapi.json",
        "/users", "/user", "/accounts", "/account",
        "/auth", "/login", "/logout", "/register",
        "/oauth", "/oauth2", "/token", "/tokens",
        "/search", "/query", "/filter",
        "/upload", "/download", "/files", "/images",
        "/config", "/configuration", "/settings",
        "/debug", "/debug/vars",
    ]

    # Interesting status codes
    INTERESTING_CODES = [200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503]

    @property
    def tool_name(self) -> str:
        return "kr"

    def _build_target_args(self, target: str, **kwargs) -> List[str]:
        """Build kiterunner command arguments."""
        args = ["scan", target]

        # Wordlist or Kitebuilder routes
        if kwargs.get("wordlist"):
            args.extend(["-w", kwargs["wordlist"]])
        elif kwargs.get("kitebuilder_list"):
            args.extend(["-A", kwargs["kitebuilder_list"]])
        else:
            # Use default kitebuilder routes if available
            default_routes = Path.home() / ".kiterunner" / "routes-large.kite"
            if default_routes.exists():
                args.extend(["-A", str(default_routes)])

        # Threads/concurrency
        if kwargs.get("threads"):
            args.extend(["-x", str(kwargs["threads"])])
        else:
            args.extend(["-x", "10"])

        # Delay between requests
        if kwargs.get("delay"):
            args.extend(["--delay", str(kwargs["delay"])])

        # Headers
        if kwargs.get("headers"):
            for header in kwargs["headers"]:
                args.extend(["-H", header])

        # Authentication
        if kwargs.get("auth_header"):
            args.extend(["-H", kwargs["auth_header"]])

        # Filter by status codes
        if kwargs.get("filter_codes"):
            args.extend(["--fail-status-codes", kwargs["filter_codes"]])

        # Output format
        args.extend(["-o", "json"])

        return args

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run kiterunner scan."""
        from datetime import datetime

        self.start_time = datetime.now()
        results = []
        raw_output = ""

        # Check if kiterunner is installed
        if self.check_tool_installed():
            print(f"[*] Running Kiterunner on {target}")
            cmd = self.build_command(target, **kwargs)
            print(f"[*] Command: {' '.join(cmd)}")

            import subprocess
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=kwargs.get("timeout", 600)
                )
                raw_output = result.stdout
                results = self._parse_kiterunner_output(result.stdout)
            except subprocess.TimeoutExpired:
                print("[!] Kiterunner timed out")
            except Exception as e:
                print(f"[!] Kiterunner error: {e}")
        else:
            print("[!] Kiterunner not installed, using fallback discovery")

        # Fallback to common API path discovery
        if not results or kwargs.get("include_fallback", False):
            fallback_results = self._fallback_discovery(target, **kwargs)
            results.extend(fallback_results)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Filter interesting results
        interesting = [r for r in results if r.interesting or r.status_code in self.INTERESTING_CODES]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"kiterunner_{timestamp}.json"

        results_data = {
            'target': target,
            'total_endpoints': len(results),
            'interesting_endpoints': len(interesting),
            'endpoints': [
                {
                    'url': r.url,
                    'method': r.method,
                    'status_code': r.status_code,
                    'content_length': r.content_length,
                    'content_type': r.content_type,
                    'response_time': r.response_time,
                    'matched_route': r.matched_route,
                    'interesting': r.interesting,
                    'notes': r.notes
                }
                for r in results
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        print(f"[+] Results saved to: {output_file}")

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'duration': duration,
            'output_file': str(output_file),
            'results': results,
            'interesting_count': len(interesting),
            'raw_output': raw_output
        }

    def _parse_kiterunner_output(self, output: str) -> List[APIEndpointFinding]:
        """Parse kiterunner JSON output."""
        results = []

        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)

                # Handle different output formats
                if isinstance(data, dict):
                    if 'results' in data:
                        for r in data['results']:
                            results.append(self._parse_result_entry(r))
                    else:
                        results.append(self._parse_result_entry(data))
                elif isinstance(data, list):
                    for item in data:
                        results.append(self._parse_result_entry(item))

            except json.JSONDecodeError:
                # Try to parse text format
                match = re.match(
                    r'(\w+)\s+(\d+)\s+\[.*?\]\s+(https?://\S+)',
                    line
                )
                if match:
                    results.append(APIEndpointFinding(
                        url=match.group(3),
                        method=match.group(1),
                        status_code=int(match.group(2)),
                        content_length=0,
                        interesting=int(match.group(2)) in self.INTERESTING_CODES
                    ))

        return results

    def _parse_result_entry(self, data: dict) -> APIEndpointFinding:
        """Parse a single result entry."""
        status = data.get('status', data.get('status_code', 0))
        return APIEndpointFinding(
            url=data.get('url', data.get('path', '')),
            method=data.get('method', 'GET'),
            status_code=status,
            content_length=data.get('length', data.get('content_length', 0)),
            content_type=data.get('content_type', ''),
            response_time=data.get('time', 0),
            matched_route=data.get('route', ''),
            interesting=status in self.INTERESTING_CODES,
            notes=data.get('title', '')
        )

    def _fallback_discovery(self, target: str, **kwargs) -> List[APIEndpointFinding]:
        """Fallback API discovery using common paths."""
        import requests

        results = []
        headers = {}

        # Parse headers
        if kwargs.get("headers"):
            for h in kwargs["headers"]:
                if ':' in h:
                    name, value = h.split(':', 1)
                    headers[name.strip()] = value.strip()

        if kwargs.get("auth_header"):
            if ':' in kwargs["auth_header"]:
                name, value = kwargs["auth_header"].split(':', 1)
                headers[name.strip()] = value.strip()

        # Normalize target URL
        if not target.startswith('http'):
            target = f"https://{target}"
        target = target.rstrip('/')

        print(f"[*] Running fallback API discovery with {len(self.COMMON_API_PATHS)} paths...")

        for path in self.COMMON_API_PATHS:
            url = f"{target}{path}"
            try:
                # Try GET first
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=kwargs.get("timeout", 10),
                    verify=False,
                    allow_redirects=False
                )

                if response.status_code != 404:
                    content_type = response.headers.get('Content-Type', '')
                    is_interesting = (
                        response.status_code in self.INTERESTING_CODES or
                        'json' in content_type.lower() or
                        'xml' in content_type.lower()
                    )

                    results.append(APIEndpointFinding(
                        url=url,
                        method='GET',
                        status_code=response.status_code,
                        content_length=len(response.content),
                        content_type=content_type,
                        response_time=response.elapsed.total_seconds(),
                        source='fallback',
                        interesting=is_interesting,
                        notes=self._get_endpoint_notes(response)
                    ))

            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue

        print(f"[+] Fallback discovery found {len(results)} endpoints")
        return results

    def _get_endpoint_notes(self, response) -> str:
        """Generate notes about an endpoint based on response."""
        notes = []

        content_type = response.headers.get('Content-Type', '').lower()

        if response.status_code == 200:
            if 'json' in content_type:
                notes.append('JSON API')
            if 'xml' in content_type:
                notes.append('XML API')
            if 'swagger' in response.url.lower() or 'openapi' in response.url.lower():
                notes.append('API Documentation')
            if 'graphql' in response.url.lower():
                notes.append('GraphQL endpoint')

        elif response.status_code == 401:
            notes.append('Requires authentication')
        elif response.status_code == 403:
            notes.append('Forbidden - may need different auth')
        elif response.status_code == 405:
            notes.append('Method not allowed - try POST/PUT')

        # Check for interesting headers
        if 'X-RateLimit' in str(response.headers) or 'RateLimit' in str(response.headers):
            notes.append('Rate limited')
        if response.headers.get('Server'):
            notes.append(f"Server: {response.headers.get('Server')}")

        return '; '.join(notes)

    def scan_with_spec(self, target: str, spec_file: str, **kwargs) -> Dict[str, Any]:
        """Scan using an OpenAPI/Swagger specification."""
        import yaml

        print(f"[*] Loading specification from {spec_file}")

        try:
            with open(spec_file, 'r') as f:
                if spec_file.endswith('.yaml') or spec_file.endswith('.yml'):
                    spec = yaml.safe_load(f)
                else:
                    spec = json.load(f)
        except Exception as e:
            return {'success': False, 'error': f'Failed to load spec: {e}'}

        endpoints = self._extract_endpoints_from_spec(spec, target)
        results = self._test_spec_endpoints(endpoints, **kwargs)

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'spec_file': spec_file,
            'results': results,
            'total_endpoints': len(endpoints),
            'accessible_count': len([r for r in results if r.status_code == 200])
        }

    def _extract_endpoints_from_spec(self, spec: dict, base_url: str) -> List[Dict]:
        """Extract endpoints from OpenAPI/Swagger specification."""
        endpoints = []
        paths = spec.get('paths', {})

        # Get base path
        base_path = ''
        if spec.get('basePath'):
            base_path = spec['basePath']
        elif spec.get('servers'):
            # OpenAPI 3.0
            server_url = spec['servers'][0].get('url', '')
            if server_url and not server_url.startswith('http'):
                base_path = server_url

        for path, methods in paths.items():
            full_path = f"{base_path}{path}".replace('//', '/')
            full_url = f"{base_url.rstrip('/')}{full_path}"

            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    params = []
                    for param in details.get('parameters', []):
                        params.append({
                            'name': param.get('name'),
                            'in': param.get('in'),
                            'required': param.get('required', False),
                            'type': param.get('schema', {}).get('type', param.get('type', 'string'))
                        })

                    endpoints.append({
                        'url': full_url,
                        'method': method.upper(),
                        'operation_id': details.get('operationId', ''),
                        'summary': details.get('summary', ''),
                        'parameters': params,
                        'security': details.get('security', [])
                    })

        return endpoints

    def _test_spec_endpoints(self, endpoints: List[Dict], **kwargs) -> List[APIEndpointFinding]:
        """Test endpoints extracted from specification."""
        import requests

        results = []
        headers = kwargs.get('headers', {})
        timeout = kwargs.get('timeout', 10)

        for endpoint in endpoints:
            try:
                response = requests.request(
                    method=endpoint['method'],
                    url=endpoint['url'],
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False
                )

                results.append(APIEndpointFinding(
                    url=endpoint['url'],
                    method=endpoint['method'],
                    status_code=response.status_code,
                    content_length=len(response.content),
                    content_type=response.headers.get('Content-Type', ''),
                    response_time=response.elapsed.total_seconds(),
                    matched_route=endpoint.get('operation_id', ''),
                    interesting=response.status_code in self.INTERESTING_CODES,
                    notes=endpoint.get('summary', ''),
                    parameters=[p['name'] for p in endpoint.get('parameters', [])]
                ))

            except Exception as e:
                results.append(APIEndpointFinding(
                    url=endpoint['url'],
                    method=endpoint['method'],
                    status_code=0,
                    content_length=0,
                    interesting=False,
                    notes=f'Error: {str(e)[:100]}'
                ))

        return results


def main():
    parser = argparse.ArgumentParser(
        description="Kiterunner Wrapper - API Endpoint Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python kiterunner.py -u https://api.example.com
  python kiterunner.py -u https://example.com -w /path/to/wordlist.txt
  python kiterunner.py -u https://example.com -A routes-large.kite -x 20
  python kiterunner.py -u https://example.com --spec swagger.json
  python kiterunner.py -u https://example.com -H "Authorization: Bearer token"
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", help="Wordlist for brute-forcing")
    parser.add_argument("-A", "--kitebuilder", dest="kitebuilder_list",
                       help="Kitebuilder routes file (.kite)")
    parser.add_argument("-x", "--threads", type=int, default=10,
                       help="Number of concurrent threads (default: 10)")
    parser.add_argument("--delay", type=int, help="Delay between requests in ms")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (format: 'Name: Value')")
    parser.add_argument("--auth", dest="auth_header",
                       help="Authorization header value")
    parser.add_argument("--spec", help="OpenAPI/Swagger spec file to use")
    parser.add_argument("--fallback", action="store_true",
                       help="Include fallback common path discovery")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-t", "--timeout", type=int, default=600,
                       help="Timeout in seconds (default: 600)")

    args = parser.parse_args()

    wrapper = KiterunnerWrapper()

    if args.spec:
        result = wrapper.scan_with_spec(
            target=args.url,
            spec_file=args.spec,
            headers=args.headers or [],
            timeout=args.timeout
        )
    else:
        result = wrapper.run(
            target=args.url,
            output_file=args.output,
            wordlist=args.wordlist,
            kitebuilder_list=args.kitebuilder_list,
            threads=args.threads,
            delay=args.delay,
            headers=args.headers or [],
            auth_header=args.auth_header,
            include_fallback=args.fallback,
            timeout=args.timeout
        )

    if result['success']:
        print(f"\n[+] API Discovery Complete")
        print(f"    Total endpoints: {len(result.get('results', []))}")
        print(f"    Interesting: {result.get('interesting_count', 0)}")

        # Show interesting endpoints
        interesting = [r for r in result.get('results', [])
                      if r.interesting or r.status_code in [200, 201, 401, 403]]
        if interesting:
            print("\n[!] Notable Endpoints:")
            for ep in interesting[:20]:
                print(f"    [{ep.method}] {ep.status_code} - {ep.url}")
                if ep.notes:
                    print(f"         Notes: {ep.notes}")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
