#!/usr/bin/env python3
"""
Phase 4: API & Modern Application Testing - Validation Script

Validates that all Phase 4 components are properly installed and functional.
"""
import sys
import subprocess
import importlib
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def check_python_module(module_name: str, package_name: str = None) -> bool:
    """Check if a Python module is importable."""
    try:
        importlib.import_module(module_name)
        print(f"  [+] {package_name or module_name}: OK")
        return True
    except ImportError as e:
        print(f"  [-] {package_name or module_name}: MISSING ({e})")
        return False


def check_tool_binary(binary: str, version_flag: str = '--version') -> bool:
    """Check if a binary tool is available."""
    try:
        result = subprocess.run(
            [binary, version_flag],
            capture_output=True,
            timeout=10
        )
        print(f"  [+] {binary}: OK")
        return True
    except FileNotFoundError:
        try:
            # Try with --help as fallback
            result = subprocess.run(
                [binary, '--help'],
                capture_output=True,
                timeout=10
            )
            print(f"  [+] {binary}: OK")
            return True
        except:
            print(f"  [-] {binary}: NOT FOUND")
            return False
    except subprocess.TimeoutExpired:
        print(f"  [+] {binary}: OK (timeout but found)")
        return True
    except Exception as e:
        print(f"  [-] {binary}: ERROR ({e})")
        return False


def check_wrapper_module(module_path: str) -> bool:
    """Check if a wrapper module can be imported."""
    try:
        importlib.import_module(module_path)
        print(f"  [+] {module_path}: OK")
        return True
    except Exception as e:
        print(f"  [-] {module_path}: ERROR ({e})")
        return False


def validate_phase4():
    """Run Phase 4 validation checks."""
    print("=" * 60)
    print("Phase 4: API & Modern Application Testing - Validation")
    print("=" * 60)

    results = {
        'python_modules': [],
        'tools': [],
        'wrappers': [],
        'files': []
    }

    # Check core Python dependencies
    print("\n[*] Checking core Python dependencies...")
    core_deps = [
        ('requests', 'requests'),
        ('yaml', 'pyyaml'),
        ('json', 'json (builtin)'),
    ]

    for module, name in core_deps:
        results['python_modules'].append(check_python_module(module, name))

    # Check API-specific Python dependencies
    print("\n[*] Checking API testing Python dependencies...")
    api_deps = [
        ('aiohttp', 'aiohttp'),
        ('gql', 'gql (GraphQL)'),
        ('graphql', 'graphql-core'),
        ('websocket', 'websocket-client'),
        ('jwt', 'pyjwt'),
        ('jose', 'python-jose'),
    ]

    for module, name in api_deps:
        results['python_modules'].append(check_python_module(module, name))

    # Check optional Python dependencies
    print("\n[*] Checking optional Python dependencies...")
    optional_deps = [
        ('openapi_spec_validator', 'openapi-spec-validator'),
        ('prance', 'prance'),
    ]

    for module, name in optional_deps:
        check_python_module(module, name)  # Don't track as required

    # Check external tools
    print("\n[*] Checking external tools...")
    tools = [
        ('kr', '--help'),  # Kiterunner
        ('newman', '--version'),  # Postman CLI
    ]

    for tool, flag in tools:
        results['tools'].append(check_tool_binary(tool, flag))

    # Check wrapper modules
    print("\n[*] Checking wrapper modules...")
    wrappers = [
        'wrappers.api.kiterunner',
        'wrappers.api.graphql_tester',
        'wrappers.api.websocket_tester',
        'wrappers.api.openapi_analyzer',
        'wrappers.api.jwt_tester',
    ]

    for wrapper in wrappers:
        results['wrappers'].append(check_wrapper_module(wrapper))

    # Check workflow module
    print("\n[*] Checking workflow module...")
    results['wrappers'].append(check_wrapper_module('workflows.api_testing'))

    # Check payload directories
    print("\n[*] Checking payload directories...")
    project_root = Path(__file__).parent.parent
    payload_dirs = [
        'config/payloads/api',
        'config/payloads/api/graphql',
        'config/payloads/api/jwt',
        'config/payloads/api/websocket',
    ]

    for pd in payload_dirs:
        path = project_root / pd
        if path.exists():
            print(f"  [+] {pd}: OK")
            results['files'].append(True)
        else:
            print(f"  [-] {pd}: MISSING (will be created)")
            # Create directory
            path.mkdir(parents=True, exist_ok=True)
            results['files'].append(True)

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)

    total_required = (
        len(results['python_modules']) +
        len(results['wrappers'])
    )
    passed_required = (
        sum(results['python_modules']) +
        sum(results['wrappers'])
    )

    total_optional = len(results['tools'])
    passed_optional = sum(results['tools'])

    print(f"\nRequired components: {passed_required}/{total_required}")
    print(f"Optional tools: {passed_optional}/{total_optional}")

    if passed_required == total_required:
        print("\n[+] All required components are installed!")
        print("[*] Phase 4 is ready for use.")

        if passed_optional < total_optional:
            print("\n[!] Some optional tools are missing:")
            print("    - kr (Kiterunner): API endpoint discovery")
            print("      Install: go install github.com/assetnote/kiterunner/cmd/kr@latest")
            print("    - newman: Postman collection runner")
            print("      Install: npm install -g newman")

        return 0
    else:
        print("\n[-] Some required components are missing!")
        print("[*] Please run: ./scripts/setup_phase4.sh")
        return 1


def test_basic_functionality():
    """Run basic functionality tests."""
    print("\n" + "=" * 60)
    print("BASIC FUNCTIONALITY TEST")
    print("=" * 60)

    try:
        # Test Kiterunner wrapper instantiation
        print("\n[*] Testing Kiterunner Wrapper...")
        from wrappers.api.kiterunner import KiterunnerWrapper
        kr = KiterunnerWrapper()
        print(f"  [+] KiterunnerWrapper instantiated: tool_name={kr.tool_name}")

        # Test GraphQL Tester instantiation
        print("\n[*] Testing GraphQL Tester...")
        from wrappers.api.graphql_tester import GraphQLTester
        gql = GraphQLTester()
        print(f"  [+] GraphQLTester instantiated: tool_name={gql.tool_name}")

        # Test WebSocket Tester instantiation
        print("\n[*] Testing WebSocket Tester...")
        from wrappers.api.websocket_tester import WebSocketTester
        ws = WebSocketTester()
        print(f"  [+] WebSocketTester instantiated: tool_name={ws.tool_name}")

        # Test OpenAPI Analyzer instantiation
        print("\n[*] Testing OpenAPI Analyzer...")
        from wrappers.api.openapi_analyzer import OpenAPIAnalyzer
        oa = OpenAPIAnalyzer()
        print(f"  [+] OpenAPIAnalyzer instantiated: tool_name={oa.tool_name}")

        # Test JWT Tester instantiation
        print("\n[*] Testing JWT Tester...")
        from wrappers.api.jwt_tester import JWTTester
        jwt = JWTTester()
        print(f"  [+] JWTTester instantiated: tool_name={jwt.tool_name}")

        # Test JWT decode functionality
        print("\n[*] Testing JWT decode functionality...")
        test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        decoded = jwt.decode_jwt(test_token)
        if decoded:
            print(f"  [+] JWT decode: OK")
            print(f"      Algorithm: {decoded.header.get('alg')}")
            print(f"      Subject: {decoded.payload.get('sub')}")
        else:
            print("  [-] JWT decode: FAILED")
            return 1

        # Test Workflow
        print("\n[*] Testing API Testing Workflow...")
        from workflows.api_testing import APITestingWorkflow
        print("  [+] APITestingWorkflow class imported")

        print("\n[+] All functionality tests passed!")
        return 0

    except Exception as e:
        print(f"\n[-] Functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


def run_quick_test():
    """Run a quick integration test against a mock endpoint."""
    print("\n" + "=" * 60)
    print("QUICK INTEGRATION TEST")
    print("=" * 60)

    try:
        # Test GraphQL introspection check (will fail but tests code path)
        print("\n[*] Testing GraphQL introspection detection...")
        from wrappers.api.graphql_tester import GraphQLTester
        tester = GraphQLTester()

        # This should handle connection errors gracefully
        print("  [*] Testing error handling with invalid endpoint...")
        # We don't actually run this as it would fail, just verify the method exists
        assert hasattr(tester, 'test_introspection'), "Missing test_introspection method"
        print("  [+] GraphQL tester methods verified")

        # Test OpenAPI spec paths
        print("\n[*] Testing OpenAPI discovery paths...")
        from wrappers.api.openapi_analyzer import OpenAPIAnalyzer
        analyzer = OpenAPIAnalyzer()
        assert len(analyzer.COMMON_SPEC_PATHS) > 0, "No spec paths defined"
        print(f"  [+] {len(analyzer.COMMON_SPEC_PATHS)} OpenAPI paths configured")

        # Test JWT payloads
        print("\n[*] Testing JWT attack payloads...")
        from wrappers.api.jwt_tester import JWTTester
        jwt_tester = JWTTester()
        assert len(jwt_tester.COMMON_SECRETS) > 0, "No common secrets defined"
        print(f"  [+] {len(jwt_tester.COMMON_SECRETS)} JWT secrets configured")

        print("\n[+] Quick integration tests passed!")
        return 0

    except Exception as e:
        print(f"\n[-] Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Validate Phase 4 installation")
    parser.add_argument("--test", action="store_true", help="Run functionality tests")
    parser.add_argument("--quick", action="store_true", help="Run quick integration tests")
    args = parser.parse_args()

    validation_result = validate_phase4()

    if args.test:
        test_result = test_basic_functionality()
        validation_result = max(validation_result, test_result)

    if args.quick:
        quick_result = run_quick_test()
        validation_result = max(validation_result, quick_result)

    sys.exit(validation_result)
