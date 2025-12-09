"""
OpenAPI/Swagger Specification Analyzer

Comprehensive security analysis of API specifications including:
- Automatic spec discovery
- Security scheme analysis
- Endpoint security assessment
- Authentication requirements checking
- Sensitive data exposure detection
- IDOR potential detection
- Rate limiting assessment
- Endpoint testing
"""
import sys
import argparse
import json
import re
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import APITool
from utils.output_parser import Finding, Severity


@dataclass
class SecurityIssue:
    """Represents a security issue found in the API specification"""
    issue_type: str
    title: str
    description: str
    severity: str
    endpoint: str = ""
    method: str = ""
    evidence: str = ""
    remediation: str = ""


@dataclass
class APIEndpoint:
    """Represents an API endpoint from the specification"""
    path: str
    method: str
    operation_id: str = ""
    summary: str = ""
    description: str = ""
    parameters: List[Dict] = field(default_factory=list)
    request_body: Dict = field(default_factory=dict)
    responses: Dict = field(default_factory=dict)
    security: List[Dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    deprecated: bool = False


class OpenAPIAnalyzer(APITool):
    """OpenAPI/Swagger specification security analyzer."""

    # Common spec paths for discovery
    COMMON_SPEC_PATHS = [
        '/swagger.json',
        '/swagger.yaml',
        '/swagger/v1/swagger.json',
        '/swagger/v2/swagger.json',
        '/swagger/v3/swagger.json',
        '/api-docs',
        '/api-docs.json',
        '/api/swagger.json',
        '/api/swagger.yaml',
        '/api/v1/swagger.json',
        '/api/v2/swagger.json',
        '/v1/swagger.json',
        '/v2/swagger.json',
        '/v3/swagger.json',
        '/openapi.json',
        '/openapi.yaml',
        '/openapi/v1.json',
        '/openapi/v2.json',
        '/openapi/v3.json',
        '/api/openapi.json',
        '/api/openapi.yaml',
        '/docs/swagger.json',
        '/docs/openapi.json',
        '/.well-known/openapi.json',
        '/.well-known/openapi.yaml',
        '/api/docs/swagger.json',
        '/api/v1/api-docs',
        '/api/v2/api-docs',
        '/v1/api-docs',
        '/v2/api-docs',
        '/api-docs/swagger.json',
        '/api-docs/swagger.yaml',
        '/swagger-ui/swagger.json',
        '/swagger-resources',
        '/swagger-resources/configuration/ui',
    ]

    # Sensitive field names patterns
    SENSITIVE_PATTERNS = [
        r'password', r'passwd', r'secret', r'token', r'api[_-]?key',
        r'auth', r'credential', r'private', r'ssn', r'social[_-]?security',
        r'credit[_-]?card', r'card[_-]?number', r'cvv', r'pin',
        r'bank[_-]?account', r'routing[_-]?number', r'salary', r'income',
        r'hash', r'salt', r'encryption[_-]?key', r'private[_-]?key',
        r'access[_-]?token', r'refresh[_-]?token', r'session',
    ]

    # IDOR-prone parameter patterns
    IDOR_PATTERNS = [
        r'id$', r'_id$', r'Id$', r'ID$',
        r'user[_-]?id', r'account[_-]?id', r'customer[_-]?id',
        r'order[_-]?id', r'transaction[_-]?id', r'payment[_-]?id',
        r'document[_-]?id', r'file[_-]?id', r'record[_-]?id',
        r'uuid', r'guid',
    ]

    @property
    def tool_name(self) -> str:
        return "openapi_analyzer"

    def _build_target_args(self, target: str, **kwargs) -> List[str]:
        """OpenAPI analyzer is pure Python."""
        return []

    def check_tool_installed(self) -> bool:
        """Check dependencies."""
        try:
            import requests
            import yaml
            return True
        except ImportError:
            return False

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run OpenAPI/Swagger security analysis."""
        from datetime import datetime

        self.start_time = datetime.now()
        issues = []
        endpoints = []
        spec_data = None

        spec_file = kwargs.get('spec_file')
        spec_url = kwargs.get('spec_url')

        print(f"[*] Analyzing API specification for: {target}")

        # Load specification
        if spec_file:
            print(f"[*] Loading spec from file: {spec_file}")
            spec_data = self._load_spec_from_file(spec_file)
        elif spec_url:
            print(f"[*] Fetching spec from URL: {spec_url}")
            spec_data = self._fetch_spec_from_url(spec_url)
        else:
            print("[*] Attempting to discover API specification...")
            spec_data, discovered_url = self._discover_spec(target)
            if spec_data:
                print(f"[+] Specification found at: {discovered_url}")

        if not spec_data:
            return {
                'success': False,
                'error': 'Could not load or discover API specification',
                'tool': self.tool_name,
                'target': target
            }

        # Extract endpoints
        endpoints = self._extract_endpoints(spec_data)
        print(f"[+] Found {len(endpoints)} endpoints")

        # Run security analysis
        print("\n[*] Analyzing security configuration...")
        issues.extend(self._analyze_security_schemes(spec_data))

        print("[*] Analyzing endpoint security...")
        issues.extend(self._analyze_endpoint_security(endpoints, spec_data))

        print("[*] Checking for sensitive data exposure...")
        issues.extend(self._check_sensitive_data(endpoints, spec_data))

        print("[*] Analyzing IDOR potential...")
        issues.extend(self._analyze_idor_potential(endpoints))

        print("[*] Checking authentication requirements...")
        issues.extend(self._check_auth_requirements(endpoints, spec_data))

        print("[*] Analyzing for information disclosure...")
        issues.extend(self._check_info_disclosure(spec_data))

        # Test endpoints if requested
        if kwargs.get('test_endpoints', False):
            print("\n[*] Testing endpoints...")
            test_results = self._test_endpoints(target, endpoints, kwargs.get('headers', {}))
            issues.extend(test_results)

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Group issues by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for issue in issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"openapi_analysis_{timestamp}.json"

        results_data = {
            'target': target,
            'spec_version': spec_data.get('openapi', spec_data.get('swagger', 'unknown')),
            'api_title': spec_data.get('info', {}).get('title', 'Unknown'),
            'api_version': spec_data.get('info', {}).get('version', 'Unknown'),
            'duration': duration,
            'total_endpoints': len(endpoints),
            'total_issues': len(issues),
            'severity_breakdown': severity_counts,
            'endpoints': [
                {
                    'path': ep.path,
                    'method': ep.method,
                    'operation_id': ep.operation_id,
                    'summary': ep.summary,
                    'security': ep.security,
                    'parameters': ep.parameters,
                    'deprecated': ep.deprecated
                }
                for ep in endpoints
            ],
            'issues': [
                {
                    'issue_type': i.issue_type,
                    'title': i.title,
                    'description': i.description,
                    'severity': i.severity,
                    'endpoint': i.endpoint,
                    'method': i.method,
                    'evidence': i.evidence,
                    'remediation': i.remediation
                }
                for i in issues
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        print(f"\n[+] Results saved to: {output_file}")

        return {
            'success': True,
            'tool': self.tool_name,
            'target': target,
            'duration': duration,
            'output_file': str(output_file),
            'endpoints': endpoints,
            'issues': issues,
            'severity_counts': severity_counts
        }

    def _load_spec_from_file(self, filepath: str) -> Optional[Dict]:
        """Load specification from file."""
        try:
            with open(filepath, 'r') as f:
                if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                    return yaml.safe_load(f)
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading spec: {e}")
            return None

    def _fetch_spec_from_url(self, url: str) -> Optional[Dict]:
        """Fetch specification from URL."""
        import requests

        try:
            response = requests.get(url, timeout=30, verify=False)
            if response.status_code == 200:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    return yaml.safe_load(response.text)
        except Exception as e:
            print(f"[!] Error fetching spec: {e}")
        return None

    def _discover_spec(self, base_url: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Attempt to discover API specification."""
        import requests

        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip('/')

        for path in self.COMMON_SPEC_PATHS:
            url = f"{base_url}{path}"
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'openapi' in data or 'swagger' in data or 'paths' in data:
                            return data, url
                    except json.JSONDecodeError:
                        try:
                            data = yaml.safe_load(response.text)
                            if data and ('openapi' in data or 'swagger' in data or 'paths' in data):
                                return data, url
                        except:
                            pass
            except:
                continue

        return None, None

    def _extract_endpoints(self, spec: Dict) -> List[APIEndpoint]:
        """Extract endpoints from specification."""
        endpoints = []
        paths = spec.get('paths', {})
        global_security = spec.get('security', [])

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                    endpoint = APIEndpoint(
                        path=path,
                        method=method.upper(),
                        operation_id=details.get('operationId', ''),
                        summary=details.get('summary', ''),
                        description=details.get('description', ''),
                        parameters=details.get('parameters', []),
                        request_body=details.get('requestBody', {}),
                        responses=details.get('responses', {}),
                        security=details.get('security', global_security),
                        tags=details.get('tags', []),
                        deprecated=details.get('deprecated', False)
                    )
                    endpoints.append(endpoint)

        return endpoints

    def _analyze_security_schemes(self, spec: Dict) -> List[SecurityIssue]:
        """Analyze security scheme definitions."""
        issues = []

        # Check for security definitions
        security_schemes = {}
        if 'securityDefinitions' in spec:  # Swagger 2.0
            security_schemes = spec['securityDefinitions']
        elif 'components' in spec and 'securitySchemes' in spec['components']:  # OpenAPI 3.0
            security_schemes = spec['components']['securitySchemes']

        if not security_schemes:
            issues.append(SecurityIssue(
                issue_type='no_security_schemes',
                title='No Security Schemes Defined',
                description='API specification does not define any security schemes',
                severity='high',
                remediation='Define appropriate security schemes (OAuth2, API Key, Bearer Token, etc.)'
            ))
            return issues

        for scheme_name, scheme in security_schemes.items():
            scheme_type = scheme.get('type', '')

            # Check for basic auth (less secure)
            if scheme_type == 'basic' or scheme.get('scheme') == 'basic':
                issues.append(SecurityIssue(
                    issue_type='basic_auth',
                    title='Basic Authentication Used',
                    description=f'Security scheme "{scheme_name}" uses Basic Authentication which transmits credentials in easily decodable format',
                    severity='medium',
                    evidence=f'Scheme: {scheme_name}, Type: basic',
                    remediation='Consider using more secure authentication methods like OAuth2 or JWT'
                ))

            # Check for API key in query parameter
            if scheme_type == 'apiKey' and scheme.get('in') == 'query':
                issues.append(SecurityIssue(
                    issue_type='api_key_in_query',
                    title='API Key in Query Parameter',
                    description=f'Security scheme "{scheme_name}" passes API key in query string which may be logged',
                    severity='medium',
                    evidence=f'Scheme: {scheme_name}, In: query',
                    remediation='Pass API keys in headers instead of query parameters'
                ))

            # Check for HTTP instead of HTTPS in OAuth flows
            if scheme_type == 'oauth2':
                flows = scheme.get('flows', scheme)  # Handle both 2.0 and 3.0
                for flow_name, flow in flows.items():
                    if isinstance(flow, dict):
                        for url_field in ['authorizationUrl', 'tokenUrl', 'refreshUrl']:
                            url = flow.get(url_field, '')
                            if url.startswith('http://'):
                                issues.append(SecurityIssue(
                                    issue_type='oauth_http',
                                    title='OAuth URL Uses HTTP',
                                    description=f'OAuth2 {url_field} uses insecure HTTP',
                                    severity='critical',
                                    evidence=f'{url_field}: {url}',
                                    remediation='Use HTTPS for all OAuth2 URLs'
                                ))

        return issues

    def _analyze_endpoint_security(self, endpoints: List[APIEndpoint], spec: Dict) -> List[SecurityIssue]:
        """Analyze security requirements for each endpoint."""
        issues = []

        sensitive_methods = ['POST', 'PUT', 'DELETE', 'PATCH']

        for endpoint in endpoints:
            # Check if endpoint has no security
            if not endpoint.security:
                severity = 'high' if endpoint.method in sensitive_methods else 'medium'
                issues.append(SecurityIssue(
                    issue_type='no_endpoint_security',
                    title='Endpoint Has No Security',
                    description=f'Endpoint {endpoint.method} {endpoint.path} has no security requirements defined',
                    severity=severity,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    remediation='Add appropriate security requirements to the endpoint'
                ))

            # Check for empty security (explicitly public)
            if endpoint.security == [{}]:
                if endpoint.method in sensitive_methods:
                    issues.append(SecurityIssue(
                        issue_type='public_sensitive_endpoint',
                        title='Sensitive Endpoint Publicly Accessible',
                        description=f'Modifying endpoint {endpoint.method} {endpoint.path} is explicitly marked as public',
                        severity='high',
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        remediation='Review if this endpoint should truly be public'
                    ))

        return issues

    def _check_sensitive_data(self, endpoints: List[APIEndpoint], spec: Dict) -> List[SecurityIssue]:
        """Check for sensitive data exposure in responses."""
        issues = []

        # Check schemas/definitions
        schemas = {}
        if 'definitions' in spec:  # Swagger 2.0
            schemas = spec['definitions']
        elif 'components' in spec and 'schemas' in spec['components']:  # OpenAPI 3.0
            schemas = spec['components']['schemas']

        for schema_name, schema in schemas.items():
            properties = schema.get('properties', {})
            for prop_name, prop in properties.items():
                for pattern in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, prop_name, re.IGNORECASE):
                        issues.append(SecurityIssue(
                            issue_type='sensitive_field_exposed',
                            title='Sensitive Field in Schema',
                            description=f'Schema "{schema_name}" contains potentially sensitive field "{prop_name}"',
                            severity='medium',
                            evidence=f'Field: {prop_name} in schema {schema_name}',
                            remediation='Consider if this field should be exposed or masked in API responses'
                        ))
                        break

        # Check endpoint responses for sensitive data
        for endpoint in endpoints:
            for status_code, response in endpoint.responses.items():
                response_desc = str(response).lower()
                for pattern in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, response_desc, re.IGNORECASE):
                        issues.append(SecurityIssue(
                            issue_type='sensitive_response_data',
                            title='Sensitive Data in Response',
                            description=f'Endpoint may expose sensitive data in response',
                            severity='medium',
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            evidence=f'Pattern "{pattern}" found in response schema'
                        ))
                        break

        return issues

    def _analyze_idor_potential(self, endpoints: List[APIEndpoint]) -> List[SecurityIssue]:
        """Analyze endpoints for IDOR potential."""
        issues = []

        for endpoint in endpoints:
            # Check path parameters for IDOR patterns
            path_params = re.findall(r'\{([^}]+)\}', endpoint.path)

            for param in path_params:
                for pattern in self.IDOR_PATTERNS:
                    if re.search(pattern, param, re.IGNORECASE):
                        issues.append(SecurityIssue(
                            issue_type='idor_potential',
                            title='Potential IDOR Vulnerability',
                            description=f'Endpoint uses ID-based parameter "{param}" which may be vulnerable to IDOR',
                            severity='medium',
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            evidence=f'Parameter: {param}',
                            remediation='Implement proper authorization checks for object access'
                        ))
                        break

            # Check query parameters
            for param in endpoint.parameters:
                param_name = param.get('name', '')
                for pattern in self.IDOR_PATTERNS:
                    if re.search(pattern, param_name, re.IGNORECASE):
                        issues.append(SecurityIssue(
                            issue_type='idor_potential_param',
                            title='Potential IDOR in Query Parameter',
                            description=f'Endpoint uses ID-based query parameter "{param_name}"',
                            severity='low',
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            evidence=f'Query Parameter: {param_name}',
                            remediation='Implement proper authorization checks'
                        ))
                        break

        return issues

    def _check_auth_requirements(self, endpoints: List[APIEndpoint], spec: Dict) -> List[SecurityIssue]:
        """Check authentication requirements consistency."""
        issues = []

        # Group endpoints by path prefix to check consistency
        path_groups = {}
        for endpoint in endpoints:
            parts = endpoint.path.strip('/').split('/')
            if parts:
                prefix = parts[0]
                if prefix not in path_groups:
                    path_groups[prefix] = []
                path_groups[prefix].append(endpoint)

        for prefix, group_endpoints in path_groups.items():
            secured = [ep for ep in group_endpoints if ep.security]
            unsecured = [ep for ep in group_endpoints if not ep.security]

            if secured and unsecured:
                issues.append(SecurityIssue(
                    issue_type='inconsistent_auth',
                    title='Inconsistent Authentication Requirements',
                    description=f'Endpoints under /{prefix}/ have inconsistent security requirements',
                    severity='low',
                    evidence=f'Secured: {len(secured)}, Unsecured: {len(unsecured)}',
                    remediation='Review and align security requirements for related endpoints'
                ))

        return issues

    def _check_info_disclosure(self, spec: Dict) -> List[SecurityIssue]:
        """Check for information disclosure in specification."""
        issues = []

        # Check for internal URLs or IPs
        spec_str = json.dumps(spec)
        internal_patterns = [
            r'192\.168\.\d+\.\d+',
            r'10\.\d+\.\d+\.\d+',
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
            r'127\.0\.0\.1',
            r'localhost',
            r'internal',
            r'\.local',
        ]

        for pattern in internal_patterns:
            matches = re.findall(pattern, spec_str, re.IGNORECASE)
            if matches:
                issues.append(SecurityIssue(
                    issue_type='internal_disclosure',
                    title='Internal Information Disclosed',
                    description=f'Specification contains internal addresses or references',
                    severity='low',
                    evidence=f'Pattern "{pattern}" found: {matches[:3]}'
                ))
                break

        # Check for verbose error examples
        if 'error' in spec_str.lower() and 'stack' in spec_str.lower():
            issues.append(SecurityIssue(
                issue_type='verbose_errors',
                title='Verbose Error Information',
                description='Specification may expose stack traces or detailed error information',
                severity='low',
                remediation='Ensure error responses do not expose sensitive debugging information'
            ))

        return issues

    def _test_endpoints(self, base_url: str, endpoints: List[APIEndpoint],
                       headers: Dict) -> List[SecurityIssue]:
        """Test endpoints for actual vulnerabilities."""
        import requests

        issues = []

        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip('/')

        for endpoint in endpoints[:20]:  # Limit testing
            # Replace path parameters with test values
            test_path = re.sub(r'\{[^}]+\}', '1', endpoint.path)
            url = f"{base_url}{test_path}"

            try:
                if endpoint.method == 'GET':
                    response = requests.get(url, headers=headers, timeout=10, verify=False)
                elif endpoint.method in ['POST', 'PUT', 'PATCH']:
                    response = requests.request(
                        endpoint.method,
                        url,
                        headers={**headers, 'Content-Type': 'application/json'},
                        json={},
                        timeout=10,
                        verify=False
                    )
                elif endpoint.method == 'DELETE':
                    response = requests.delete(url, headers=headers, timeout=10, verify=False)
                else:
                    continue

                # Check for interesting responses
                if response.status_code == 200 and not endpoint.security:
                    issues.append(SecurityIssue(
                        issue_type='accessible_unsecured',
                        title='Unsecured Endpoint Accessible',
                        description=f'Endpoint without security returned 200 OK',
                        severity='high',
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence=f'Status: {response.status_code}, Length: {len(response.text)}'
                    ))

                if response.status_code == 500:
                    issues.append(SecurityIssue(
                        issue_type='server_error',
                        title='Server Error Response',
                        description='Endpoint returned 500 error which may expose information',
                        severity='low',
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence=response.text[:200]
                    ))

            except Exception:
                continue

        return issues


def main():
    parser = argparse.ArgumentParser(
        description="OpenAPI/Swagger Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python openapi_analyzer.py -u https://api.example.com
  python openapi_analyzer.py -u https://example.com --spec swagger.json
  python openapi_analyzer.py -u https://example.com --spec-url https://example.com/swagger.json
  python openapi_analyzer.py -u https://api.example.com --test -H "Authorization: Bearer token"
        """
    )

    parser.add_argument("-u", "--url", required=True, help="Target API base URL")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--spec", dest="spec_file", help="Local specification file path")
    parser.add_argument("--spec-url", help="Specification URL")
    parser.add_argument("--test", action="store_true", dest="test_endpoints",
                       help="Test endpoints for actual vulnerabilities")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="HTTP headers for testing (format: 'Name: Value')")

    args = parser.parse_args()

    analyzer = OpenAPIAnalyzer()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ': ' in h:
                name, value = h.split(': ', 1)
                headers[name] = value

    result = analyzer.run(
        target=args.url,
        output_file=args.output,
        spec_file=args.spec_file,
        spec_url=args.spec_url,
        test_endpoints=args.test_endpoints,
        headers=headers
    )

    if result['success']:
        print(f"\n{'='*60}")
        print(f"OpenAPI Security Analysis Complete")
        print(f"{'='*60}")
        print(f"Total endpoints: {len(result['endpoints'])}")
        print(f"Total issues: {len(result['issues'])}")
        print(f"\nIssues by severity:")
        for severity, count in result['severity_counts'].items():
            if count > 0:
                print(f"  {severity.upper()}: {count}")

        # Show high/critical issues
        critical_issues = [i for i in result['issues'] if i.severity in ['critical', 'high']]
        if critical_issues:
            print(f"\n[!] Critical/High Issues:")
            for issue in critical_issues[:10]:
                print(f"\n  [{issue.severity.upper()}] {issue.title}")
                print(f"  {issue.description}")
                if issue.endpoint:
                    print(f"  Endpoint: {issue.method} {issue.endpoint}")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
