#!/usr/bin/env python3
"""
Phase 2 Validation Script - Manual Testing Support & Proxy Integration

This script validates that all Phase 2 components are properly installed
and configured.
"""

import sys
import os
import subprocess
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")


def print_ok(text):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {text}")


def print_fail(text):
    print(f"{Colors.RED}[-]{Colors.RESET} {text}")


def print_warn(text):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {text}")


def print_info(text):
    print(f"{Colors.BLUE}[*]{Colors.RESET} {text}")


def check_python_module(module_name, import_path=None):
    """Check if a Python module is installed."""
    import_path = import_path or module_name
    try:
        exec(f"import {import_path}")
        return True
    except ImportError:
        return False


def check_command(command):
    """Check if a command is available."""
    try:
        result = subprocess.run(
            [command, '--version'],
            capture_output=True,
            timeout=10
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        try:
            result = subprocess.run(
                [command, '--help'],
                capture_output=True,
                timeout=10
            )
            return True
        except:
            return False


def validate_python_dependencies():
    """Validate Python package dependencies for Phase 2."""
    print_header("Python Dependencies")

    dependencies = [
        ('python-owasp-zap-v2.4', 'zapv2', 'ZAP API client'),
        ('pyjwt', 'jwt', 'JWT library'),
        ('python-jose', 'jose', 'JOSE/JWT library'),
        ('pycryptodome', 'Crypto', 'Cryptography library'),
        ('base58', 'base58', 'Base58 encoding'),
        ('requests', 'requests', 'HTTP library'),
        ('aiohttp', 'aiohttp', 'Async HTTP library'),
    ]

    results = []
    for package_name, import_name, description in dependencies:
        if check_python_module(import_name):
            print_ok(f"{package_name} ({description})")
            results.append((package_name, True))
        else:
            print_fail(f"{package_name} ({description}) - Not installed")
            results.append((package_name, False))

    return results


def validate_external_tools():
    """Validate external tools for Phase 2."""
    print_header("External Tools")

    tools = [
        ('ffuf', 'Fast web fuzzer'),
        ('mitmproxy', 'Interception proxy'),
        ('mitmdump', 'mitmproxy command-line tool'),
    ]

    results = []
    for tool, description in tools:
        if check_command(tool):
            print_ok(f"{tool} ({description})")
            results.append((tool, True))
        else:
            print_warn(f"{tool} ({description}) - Not found in PATH")
            results.append((tool, False))

    # Special check for ZAP
    zap_found = False
    for zap_cmd in ['zap.sh', 'zaproxy', 'zap']:
        if check_command(zap_cmd):
            print_ok(f"OWASP ZAP (found as {zap_cmd})")
            zap_found = True
            break

    if not zap_found:
        print_warn("OWASP ZAP - Not found in PATH (requires manual installation)")

    results.append(('zap', zap_found))

    return results


def validate_wrapper_imports():
    """Validate that wrapper modules can be imported."""
    print_header("Wrapper Imports")

    wrappers = [
        ('wrappers.proxy.zap_integration', 'ZAPIntegration'),
        ('wrappers.proxy.request_builder', 'RequestBuilder'),
        ('wrappers.proxy.session_manager', 'SessionManager'),
        ('utils.encoder', 'PayloadEncoder'),
    ]

    results = []
    for module_path, class_name in wrappers:
        try:
            module = __import__(module_path, fromlist=[class_name])
            cls = getattr(module, class_name)
            print_ok(f"{module_path}.{class_name}")
            results.append((module_path, True))
        except ImportError as e:
            print_fail(f"{module_path}.{class_name} - Import error: {e}")
            results.append((module_path, False))
        except AttributeError as e:
            print_fail(f"{module_path}.{class_name} - Class not found: {e}")
            results.append((module_path, False))

    return results


def test_encoder():
    """Test the PayloadEncoder functionality."""
    print_header("Encoder Tests")

    try:
        from utils.encoder import PayloadEncoder, PayloadDecoder

        test_payload = "<script>alert(1)</script>"

        # Test URL encoding
        encoded = PayloadEncoder.url_encode(test_payload)
        decoded = PayloadEncoder.url_decode(encoded)
        if decoded == test_payload:
            print_ok("URL encode/decode")
        else:
            print_fail("URL encode/decode")

        # Test Base64 encoding
        encoded = PayloadEncoder.base64_encode(test_payload)
        decoded = PayloadEncoder.base64_decode(encoded)
        if decoded == test_payload:
            print_ok("Base64 encode/decode")
        else:
            print_fail("Base64 encode/decode")

        # Test HTML encoding
        encoded = PayloadEncoder.html_encode(test_payload)
        decoded = PayloadEncoder.html_decode(encoded)
        if decoded == test_payload:
            print_ok("HTML encode/decode")
        else:
            print_fail("HTML encode/decode")

        # Test chain encoding
        encoded = PayloadEncoder.chain_encode(test_payload, ['url', 'base64'])
        if encoded:
            print_ok("Chain encoding")
        else:
            print_fail("Chain encoding")

        # Test XSS variants
        variants = PayloadEncoder.xss_variants(test_payload)
        if len(variants) > 1:
            print_ok(f"XSS variants ({len(variants)} generated)")
        else:
            print_fail("XSS variants")

        return True
    except Exception as e:
        print_fail(f"Encoder tests failed: {e}")
        return False


def test_request_builder():
    """Test the RequestBuilder functionality."""
    print_header("RequestBuilder Tests")

    try:
        from wrappers.proxy.request_builder import RequestBuilder

        builder = RequestBuilder(timeout=10)

        # Test basic request (using httpbin.org as test target)
        print_info("Testing HTTP GET request...")
        try:
            response = builder.get('https://httpbin.org/get', timeout=10)
            if response.status_code == 200:
                print_ok("HTTP GET request")
            else:
                print_warn(f"HTTP GET returned status {response.status_code}")
        except Exception as e:
            print_warn(f"HTTP GET failed (network may be unavailable): {e}")

        # Test history
        if len(builder.history) > 0:
            print_ok("Request history tracking")
        else:
            print_warn("Request history empty (expected if network unavailable)")

        # Test parameter fuzzing (without network)
        print_info("Testing parameter fuzzing setup...")
        payloads = ["test1", "test2", "test3"]
        # Just verify the method exists and is callable
        if callable(builder.fuzz_parameter):
            print_ok("Parameter fuzzing method available")
        else:
            print_fail("Parameter fuzzing method not callable")

        return True
    except Exception as e:
        print_fail(f"RequestBuilder tests failed: {e}")
        return False


def test_session_manager():
    """Test the SessionManager functionality."""
    print_header("SessionManager Tests")

    try:
        from wrappers.proxy.session_manager import SessionManager

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = SessionManager(storage_dir=tmpdir)

            # Test session creation
            manager.create_session('test_session')
            if 'test_session' in manager.sessions:
                print_ok("Session creation")
            else:
                print_fail("Session creation")

            # Test token addition
            manager.add_token('test_token', 'secret_value', token_type='bearer')
            if 'test_token' in manager.sessions['test_session'].tokens:
                print_ok("Token addition")
            else:
                print_fail("Token addition")

            # Test JWT addition
            test_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            manager.add_jwt('jwt_token', test_jwt)
            if 'jwt_token' in manager.sessions['test_session'].tokens:
                print_ok("JWT token addition")
            else:
                print_fail("JWT token addition")

            # Test auth headers
            headers = manager.get_auth_headers()
            if 'Authorization' in headers:
                print_ok("Auth headers generation")
            else:
                print_fail("Auth headers generation")

            # Test session persistence
            manager.save_sessions()
            manager2 = SessionManager(storage_dir=tmpdir)
            manager2.load_sessions()
            if 'test_session' in manager2.sessions:
                print_ok("Session persistence")
            else:
                print_fail("Session persistence")

            # Test session cloning
            manager.clone_session('test_session', 'cloned_session')
            if 'cloned_session' in manager.sessions:
                print_ok("Session cloning")
            else:
                print_fail("Session cloning")

        return True
    except Exception as e:
        print_fail(f"SessionManager tests failed: {e}")
        return False


def main():
    """Run all Phase 2 validations."""
    print_header("Phase 2 Validation: Manual Testing Support & Proxy Integration")

    all_results = {
        'python_deps': [],
        'external_tools': [],
        'wrapper_imports': [],
        'encoder_tests': False,
        'request_builder_tests': False,
        'session_manager_tests': False,
    }

    # Run validations
    all_results['python_deps'] = validate_python_dependencies()
    all_results['external_tools'] = validate_external_tools()
    all_results['wrapper_imports'] = validate_wrapper_imports()
    all_results['encoder_tests'] = test_encoder()
    all_results['request_builder_tests'] = test_request_builder()
    all_results['session_manager_tests'] = test_session_manager()

    # Summary
    print_header("Validation Summary")

    # Count results
    python_ok = sum(1 for _, ok in all_results['python_deps'] if ok)
    python_total = len(all_results['python_deps'])

    tools_ok = sum(1 for _, ok in all_results['external_tools'] if ok)
    tools_total = len(all_results['external_tools'])

    imports_ok = sum(1 for _, ok in all_results['wrapper_imports'] if ok)
    imports_total = len(all_results['wrapper_imports'])

    print(f"Python Dependencies: {python_ok}/{python_total}")
    print(f"External Tools: {tools_ok}/{tools_total}")
    print(f"Wrapper Imports: {imports_ok}/{imports_total}")
    print(f"Encoder Tests: {'PASS' if all_results['encoder_tests'] else 'FAIL'}")
    print(f"RequestBuilder Tests: {'PASS' if all_results['request_builder_tests'] else 'FAIL'}")
    print(f"SessionManager Tests: {'PASS' if all_results['session_manager_tests'] else 'FAIL'}")

    # Overall status
    critical_ok = (
        python_ok >= 4 and  # Core Python deps
        imports_ok == imports_total and  # All imports must work
        all_results['encoder_tests'] and
        all_results['session_manager_tests']
    )

    print("")
    if critical_ok:
        print_ok("Phase 2 validation PASSED - Core functionality is operational")
        print_info("Note: ZAP and mitmproxy require manual installation for full functionality")
        return 0
    else:
        print_fail("Phase 2 validation FAILED - Some components are missing")
        print_info("Run: ./scripts/setup_phase2.sh to install missing components")
        return 1


if __name__ == '__main__':
    sys.exit(main())
