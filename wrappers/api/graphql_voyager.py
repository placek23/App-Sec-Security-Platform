"""
GraphQL Voyager - GraphQL API testing and introspection
"""
import sys
import argparse
import json
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.base_wrapper import APITool
from utils.output_parser import Finding, Severity


class GraphqlVoyagerWrapper(APITool):
    """Wrapper for GraphQL API testing"""
    
    @property
    def tool_name(self) -> str:
        return "graphql_voyager"
    
    def _build_target_args(self, target: str, **kwargs) -> list:
        """Build GraphQL-specific testing arguments"""
        # This is a custom implementation since there's no standard CLI tool
        return []
    
    def run(self, target: str, output_file: str = None, **kwargs) -> dict:
        """Run GraphQL security tests"""
        findings = []
        introspection_result = None
        
        print(f"[*] Testing GraphQL endpoint: {target}")
        
        headers = kwargs.get("headers", {})
        if isinstance(headers, list):
            headers = dict(h.split(": ", 1) for h in headers if ": " in h)
        
        headers.setdefault("Content-Type", "application/json")
        
        # Test 1: Introspection Query
        print("[*] Testing introspection...")
        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        types {
                            name
                            fields {
                                name
                                args { name type { name } }
                            }
                        }
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                    }
                }
            """
        }
        
        try:
            response = requests.post(target, json=introspection_query, headers=headers, timeout=30)
            if response.status_code == 200 and "__schema" in response.text:
                introspection_result = response.json()
                findings.append(Finding(
                    tool="graphql_voyager",
                    target=target,
                    finding_type="graphql",
                    title="GraphQL Introspection Enabled",
                    description="GraphQL introspection is enabled, exposing the entire API schema",
                    severity=Severity.MEDIUM,
                    evidence=f"Found {len(introspection_result.get('data', {}).get('__schema', {}).get('types', []))} types"
                ))
                print("[+] Introspection is ENABLED")
            else:
                print("[-] Introspection appears to be disabled")
        except Exception as e:
            print(f"[-] Introspection test failed: {e}")
        
        # Test 2: Batch Query Attack
        print("[*] Testing batch query support...")
        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"}
        ]
        
        try:
            response = requests.post(target, json=batch_query, headers=headers, timeout=30)
            if response.status_code == 200 and isinstance(response.json(), list):
                findings.append(Finding(
                    tool="graphql_voyager",
                    target=target,
                    finding_type="graphql",
                    title="GraphQL Batch Query Enabled",
                    description="GraphQL batch queries are enabled, potential for DoS attacks",
                    severity=Severity.LOW,
                    evidence="Batch query response received"
                ))
                print("[+] Batch queries are ENABLED")
        except:
            pass
        
        # Test 3: Field Suggestions
        print("[*] Testing field suggestions (information disclosure)...")
        suggestion_query = {
            "query": "{ user { namee } }"  # Intentional typo
        }
        
        try:
            response = requests.post(target, json=suggestion_query, headers=headers, timeout=30)
            if "did you mean" in response.text.lower() or "suggestion" in response.text.lower():
                findings.append(Finding(
                    tool="graphql_voyager",
                    target=target,
                    finding_type="graphql",
                    title="GraphQL Field Suggestions Enabled",
                    description="GraphQL provides field suggestions, potentially leaking schema information",
                    severity=Severity.LOW,
                    evidence="Field suggestions in error response"
                ))
                print("[+] Field suggestions are ENABLED")
        except:
            pass
        
        # Test 4: Deep Recursion (DoS potential)
        print("[*] Testing for deep recursion vulnerability...")
        deep_query = {
            "query": "{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }"
        }
        
        try:
            response = requests.post(target, json=deep_query, headers=headers, timeout=10)
            if response.status_code == 200:
                findings.append(Finding(
                    tool="graphql_voyager",
                    target=target,
                    finding_type="graphql",
                    title="GraphQL Deep Query Allowed",
                    description="Deep nested queries are allowed, potential DoS vulnerability",
                    severity=Severity.MEDIUM,
                    evidence="Deep query executed successfully"
                ))
                print("[+] Deep queries are ALLOWED")
        except requests.Timeout:
            findings.append(Finding(
                tool="graphql_voyager",
                target=target,
                finding_type="graphql",
                title="GraphQL Query Complexity Not Limited",
                description="Complex queries cause timeout, indicating lack of query depth limiting",
                severity=Severity.MEDIUM,
                evidence="Query timed out"
            ))
            print("[!] Query timeout - possible DoS vector")
        except:
            pass
        
        # Save results
        if output_file:
            output_data = {
                "target": target,
                "findings": [f.to_dict() for f in findings],
                "introspection": introspection_result
            }
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"[+] Results saved to: {output_file}")
        
        return {
            "success": True,
            "tool": self.tool_name,
            "target": target,
            "results": findings,
            "introspection": introspection_result
        }


def main():
    parser = argparse.ArgumentParser(
        description="GraphQL Voyager - GraphQL security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python graphql_voyager.py -u https://example.com/graphql
  python graphql_voyager.py -u https://example.com/api/graphql -o results.json
  python graphql_voyager.py -u https://example.com/graphql -H "Authorization: Bearer token"
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="GraphQL endpoint URL")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-H", "--header", action="append", dest="headers", help="HTTP headers")
    
    args = parser.parse_args()
    
    wrapper = GraphqlVoyagerWrapper()
    
    result = wrapper.run(
        target=args.url,
        output_file=args.output,
        headers=args.headers or []
    )
    
    if result["success"]:
        findings = result["results"]
        print(f"\n[+] GraphQL Security Assessment Complete")
        print(f"    Found {len(findings)} issues")
        
        if findings:
            print("\n[!] Issues Found:")
            for finding in findings:
                print(f"\n  [{finding.severity.value.upper()}] {finding.title}")
                print(f"  {finding.description}")
    else:
        print(f"\n[-] Error: {result.get('error', 'Unknown error')}")
    
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
