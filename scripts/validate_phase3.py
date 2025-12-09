#!/usr/bin/env python3
"""
Phase 3 Validation Script - Advanced Injection Testing

This script validates that all Phase 3 components are properly installed
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
    """Validate Python package dependencies for Phase 3."""
    print_header("Python Dependencies")

    dependencies = [
        ('requests', 'requests', 'HTTP library'),
        ('urllib3', 'urllib3', 'URL handling library'),
        ('ldap3', 'ldap3', 'LDAP library'),
        ('lxml', 'lxml', 'XML/XPath library'),
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
    """Validate external tools for Phase 3."""
    print_header("External Tools")

    tools = [
        ('sqlmap', 'SQL injection testing tool'),
        ('commix', 'Command injection exploitation tool'),
    ]

    results = []
    for tool, description in tools:
        if check_command(tool):
            print_ok(f"{tool} ({description})")
            results.append((tool, True))
        else:
            print_warn(f"{tool} ({description}) - Not found in PATH")
            results.append((tool, False))

    # Check for PayloadsAllTheThings
    payloads_path = Path.home() / "tools" / "PayloadsAllTheThings"
    if payloads_path.exists():
        print_ok(f"PayloadsAllTheThings ({payloads_path})")
        results.append(('PayloadsAllTheThings', True))
    else:
        print_warn("PayloadsAllTheThings - Not found in ~/tools/")
        results.append(('PayloadsAllTheThings', False))

    # Check for NoSQLMap
    nosqlmap_path = Path.home() / "tools" / "NoSQLMap"
    if nosqlmap_path.exists():
        print_ok(f"NoSQLMap ({nosqlmap_path})")
        results.append(('NoSQLMap', True))
    else:
        print_warn("NoSQLMap - Not found in ~/tools/")
        results.append(('NoSQLMap', False))

    return results


def validate_payload_files():
    """Validate payload files exist."""
    print_header("Payload Files")

    payload_dirs = [
        'config/payloads/injection/sql',
        'config/payloads/injection/nosql',
        'config/payloads/injection/ldap',
        'config/payloads/injection/xpath',
        'config/payloads/injection/xss',
    ]

    results = []
    for dir_path in payload_dirs:
        full_path = PROJECT_ROOT / dir_path
        if full_path.exists():
            # Count payload files
            files = list(full_path.glob('*.txt'))
            print_ok(f"{dir_path} ({len(files)} files)")
            results.append((dir_path, True))
        else:
            print_fail(f"{dir_path} - Directory not found")
            results.append((dir_path, False))

    return results


def validate_wrapper_imports():
    """Validate that wrapper modules can be imported."""
    print_header("Wrapper Imports")

    wrappers = [
        ('wrappers.injection.nosql_injection', 'NoSQLInjectionTester'),
        ('wrappers.injection.ldap_injection', 'LDAPInjectionTester'),
        ('wrappers.injection.xpath_injection', 'XPathInjectionTester'),
        ('wrappers.injection.advanced_xss', 'AdvancedXSSTester'),
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


def test_nosql_injection_tester():
    """Test the NoSQLInjectionTester functionality."""
    print_header("NoSQLInjectionTester Tests")

    try:
        from wrappers.injection.nosql_injection import NoSQLInjectionTester, NoSQLFinding

        tester = NoSQLInjectionTester()

        # Test that payloads are defined
        if len(tester.MONGODB_PAYLOADS) > 0:
            print_ok(f"MongoDB payloads loaded ({len(tester.MONGODB_PAYLOADS)} payloads)")
        else:
            print_fail("No MongoDB payloads found")

        if len(tester.MONGODB_STRING_PAYLOADS) > 0:
            print_ok(f"MongoDB string payloads loaded ({len(tester.MONGODB_STRING_PAYLOADS)} payloads)")
        else:
            print_fail("No MongoDB string payloads found")

        # Test tool properties
        if tester.tool_name == "nosql_injection":
            print_ok("Tool name property")
        else:
            print_fail("Tool name property incorrect")

        # Test check_tool_installed (pure Python, should always pass)
        if tester.check_tool_installed():
            print_ok("Tool installation check (requests available)")
        else:
            print_fail("Tool installation check failed")

        return True
    except Exception as e:
        print_fail(f"NoSQLInjectionTester tests failed: {e}")
        return False


def test_ldap_injection_tester():
    """Test the LDAPInjectionTester functionality."""
    print_header("LDAPInjectionTester Tests")

    try:
        from wrappers.injection.ldap_injection import LDAPInjectionTester, LDAPFinding

        tester = LDAPInjectionTester()

        # Test that payloads are defined
        if len(tester.BASIC_PAYLOADS) > 0:
            print_ok(f"Basic LDAP payloads loaded ({len(tester.BASIC_PAYLOADS)} payloads)")
        else:
            print_fail("No basic LDAP payloads found")

        if len(tester.AUTH_BYPASS_PAYLOADS) > 0:
            print_ok(f"Auth bypass payloads loaded ({len(tester.AUTH_BYPASS_PAYLOADS)} payloads)")
        else:
            print_fail("No auth bypass payloads found")

        if len(tester.BLIND_PAYLOADS) > 0:
            print_ok(f"Blind LDAP payloads loaded ({len(tester.BLIND_PAYLOADS)} payloads)")
        else:
            print_fail("No blind LDAP payloads found")

        # Test tool properties
        if tester.tool_name == "ldap_injection":
            print_ok("Tool name property")
        else:
            print_fail("Tool name property incorrect")

        return True
    except Exception as e:
        print_fail(f"LDAPInjectionTester tests failed: {e}")
        return False


def test_xpath_injection_tester():
    """Test the XPathInjectionTester functionality."""
    print_header("XPathInjectionTester Tests")

    try:
        from wrappers.injection.xpath_injection import XPathInjectionTester, XPathFinding

        tester = XPathInjectionTester()

        # Test that payloads are defined
        if len(tester.BASIC_PAYLOADS) > 0:
            print_ok(f"Basic XPath payloads loaded ({len(tester.BASIC_PAYLOADS)} payloads)")
        else:
            print_fail("No basic XPath payloads found")

        if len(tester.AUTH_BYPASS_PAYLOADS) > 0:
            print_ok(f"Auth bypass payloads loaded ({len(tester.AUTH_BYPASS_PAYLOADS)} payloads)")
        else:
            print_fail("No auth bypass payloads found")

        if len(tester.BLIND_PAYLOADS) > 0:
            print_ok(f"Blind XPath payloads loaded ({len(tester.BLIND_PAYLOADS)} payloads)")
        else:
            print_fail("No blind XPath payloads found")

        if len(tester.FUNCTION_PAYLOADS) > 0:
            print_ok(f"Function-based payloads loaded ({len(tester.FUNCTION_PAYLOADS)} payloads)")
        else:
            print_fail("No function-based payloads found")

        # Test tool properties
        if tester.tool_name == "xpath_injection":
            print_ok("Tool name property")
        else:
            print_fail("Tool name property incorrect")

        return True
    except Exception as e:
        print_fail(f"XPathInjectionTester tests failed: {e}")
        return False


def test_advanced_xss_tester():
    """Test the AdvancedXSSTester functionality."""
    print_header("AdvancedXSSTester Tests")

    try:
        from wrappers.injection.advanced_xss import AdvancedXSSTester, XSSFinding, XSSType, XSSContext

        tester = AdvancedXSSTester()

        # Test that payloads are defined
        if len(tester.REFLECTED_PAYLOADS) > 0:
            print_ok(f"Reflected XSS payloads loaded ({len(tester.REFLECTED_PAYLOADS)} payloads)")
        else:
            print_fail("No reflected XSS payloads found")

        if len(tester.DOM_PAYLOADS) > 0:
            print_ok(f"DOM XSS payloads loaded ({len(tester.DOM_PAYLOADS)} payloads)")
        else:
            print_fail("No DOM XSS payloads found")

        if len(tester.CSP_BYPASS_PAYLOADS) > 0:
            print_ok(f"CSP bypass payloads loaded ({len(tester.CSP_BYPASS_PAYLOADS)} payloads)")
        else:
            print_fail("No CSP bypass payloads found")

        if len(tester.FILTER_BYPASS_PAYLOADS) > 0:
            print_ok(f"Filter bypass payloads loaded ({len(tester.FILTER_BYPASS_PAYLOADS)} payloads)")
        else:
            print_fail("No filter bypass payloads found")

        if len(tester.POLYGLOT_PAYLOADS) > 0:
            print_ok(f"Polyglot payloads loaded ({len(tester.POLYGLOT_PAYLOADS)} payloads)")
        else:
            print_fail("No polyglot payloads found")

        # Test DOM sources and sinks
        if len(tester.DOM_SOURCES) > 0:
            print_ok(f"DOM sources defined ({len(tester.DOM_SOURCES)} sources)")
        else:
            print_fail("No DOM sources defined")

        if len(tester.DOM_SINKS) > 0:
            print_ok(f"DOM sinks defined ({len(tester.DOM_SINKS)} sinks)")
        else:
            print_fail("No DOM sinks defined")

        # Test tool properties
        if tester.tool_name == "advanced_xss":
            print_ok("Tool name property")
        else:
            print_fail("Tool name property incorrect")

        # Test XSS type and context enums
        try:
            _ = XSSType.REFLECTED
            _ = XSSType.DOM
            _ = XSSType.CSP_BYPASS
            print_ok("XSSType enum")
        except Exception:
            print_fail("XSSType enum")

        try:
            _ = XSSContext.HTML_BODY
            _ = XSSContext.JAVASCRIPT
            _ = XSSContext.HTML_ATTRIBUTE
            print_ok("XSSContext enum")
        except Exception:
            print_fail("XSSContext enum")

        return True
    except Exception as e:
        print_fail(f"AdvancedXSSTester tests failed: {e}")
        return False


def main():
    """Run all Phase 3 validations."""
    print_header("Phase 3 Validation: Advanced Injection Testing")

    all_results = {
        'python_deps': [],
        'external_tools': [],
        'payload_files': [],
        'wrapper_imports': [],
        'nosql_tests': False,
        'ldap_tests': False,
        'xpath_tests': False,
        'xss_tests': False,
    }

    # Run validations
    all_results['python_deps'] = validate_python_dependencies()
    all_results['external_tools'] = validate_external_tools()
    all_results['payload_files'] = validate_payload_files()
    all_results['wrapper_imports'] = validate_wrapper_imports()
    all_results['nosql_tests'] = test_nosql_injection_tester()
    all_results['ldap_tests'] = test_ldap_injection_tester()
    all_results['xpath_tests'] = test_xpath_injection_tester()
    all_results['xss_tests'] = test_advanced_xss_tester()

    # Summary
    print_header("Validation Summary")

    # Count results
    python_ok = sum(1 for _, ok in all_results['python_deps'] if ok)
    python_total = len(all_results['python_deps'])

    tools_ok = sum(1 for _, ok in all_results['external_tools'] if ok)
    tools_total = len(all_results['external_tools'])

    payloads_ok = sum(1 for _, ok in all_results['payload_files'] if ok)
    payloads_total = len(all_results['payload_files'])

    imports_ok = sum(1 for _, ok in all_results['wrapper_imports'] if ok)
    imports_total = len(all_results['wrapper_imports'])

    print(f"Python Dependencies: {python_ok}/{python_total}")
    print(f"External Tools: {tools_ok}/{tools_total}")
    print(f"Payload Files: {payloads_ok}/{payloads_total}")
    print(f"Wrapper Imports: {imports_ok}/{imports_total}")
    print(f"NoSQL Injection Tests: {'PASS' if all_results['nosql_tests'] else 'FAIL'}")
    print(f"LDAP Injection Tests: {'PASS' if all_results['ldap_tests'] else 'FAIL'}")
    print(f"XPath Injection Tests: {'PASS' if all_results['xpath_tests'] else 'FAIL'}")
    print(f"Advanced XSS Tests: {'PASS' if all_results['xss_tests'] else 'FAIL'}")

    # Overall status
    critical_ok = (
        python_ok >= 2 and  # Core Python deps (requests, urllib3)
        imports_ok == imports_total and  # All imports must work
        all_results['nosql_tests'] and
        all_results['ldap_tests'] and
        all_results['xpath_tests'] and
        all_results['xss_tests']
    )

    print("")
    if critical_ok:
        print_ok("Phase 3 validation PASSED - Core functionality is operational")
        if tools_ok < tools_total:
            print_info("Note: Some external tools are optional and may require manual installation")
        return 0
    else:
        print_fail("Phase 3 validation FAILED - Some components are missing")
        print_info("Run: ./scripts/setup_phase3.sh to install missing components")
        return 1


if __name__ == '__main__':
    sys.exit(main())
