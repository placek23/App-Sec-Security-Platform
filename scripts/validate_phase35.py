#!/usr/bin/env python3
"""
Phase 3.5: Advanced Web Vulnerabilities - Validation Script

Validates that all Phase 3.5 components are properly installed and functional.
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


def check_tool_binary(binary: str) -> bool:
    """Check if a binary tool is available."""
    try:
        result = subprocess.run(
            [binary, '--version'],
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


def validate_phase35():
    """Run Phase 3.5 validation checks."""
    print("=" * 60)
    print("Phase 3.5: Advanced Web Vulnerabilities - Validation")
    print("=" * 60)

    results = {
        'python_modules': [],
        'tools': [],
        'wrappers': [],
        'files': []
    }

    # Check Python dependencies
    print("\n[*] Checking Python dependencies...")
    python_deps = [
        ('requests', 'requests'),
        ('aiohttp', 'aiohttp'),
        ('asyncio', 'asyncio'),
    ]

    for module, name in python_deps:
        results['python_modules'].append(check_python_module(module, name))

    # Optional Python dependencies
    print("\n[*] Checking optional Python dependencies...")
    optional_deps = [
        ('h2', 'h2 (HTTP/2)'),
        ('magic', 'python-magic'),
    ]

    for module, name in optional_deps:
        check_python_module(module, name)  # Don't track as required

    # Check external tools
    print("\n[*] Checking external tools...")
    tools = [
        'interactsh-client',
    ]

    for tool in tools:
        results['tools'].append(check_tool_binary(tool))

    # Check wrapper modules
    print("\n[*] Checking wrapper modules...")
    wrappers = [
        'wrappers.advanced.ssrf_tester',
        'wrappers.advanced.xxe_injector',
        'wrappers.advanced.http_smuggler',
        'wrappers.advanced.race_condition',
        'wrappers.advanced.cors_tester',
        'wrappers.advanced.file_upload_bypass',
    ]

    for wrapper in wrappers:
        results['wrappers'].append(check_wrapper_module(wrapper))

    # Check utility modules
    print("\n[*] Checking utility modules...")
    utilities = [
        'utils.oob_callback',
    ]

    for util in utilities:
        results['wrappers'].append(check_wrapper_module(util))

    # Check workflow
    print("\n[*] Checking workflow module...")
    results['wrappers'].append(check_wrapper_module('workflows.advanced_vulns'))

    # Check payload files
    print("\n[*] Checking payload files...")
    project_root = Path(__file__).parent.parent
    payload_files = [
        'config/payloads/advanced/ssrf/cloud_metadata.txt',
        'config/payloads/advanced/ssrf/bypass_techniques.txt',
        'config/payloads/advanced/xxe/basic.xml',
        'config/payloads/advanced/xxe/payloads.txt',
        'config/payloads/advanced/cors/origins.txt',
    ]

    for pf in payload_files:
        path = project_root / pf
        if path.exists():
            print(f"  [+] {pf}: OK")
            results['files'].append(True)
        else:
            print(f"  [-] {pf}: MISSING")
            results['files'].append(False)

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)

    total_required = (
        len(results['python_modules']) +
        len(results['wrappers']) +
        len(results['files'])
    )
    passed_required = (
        sum(results['python_modules']) +
        sum(results['wrappers']) +
        sum(results['files'])
    )

    total_optional = len(results['tools'])
    passed_optional = sum(results['tools'])

    print(f"\nRequired components: {passed_required}/{total_required}")
    print(f"Optional components: {passed_optional}/{total_optional}")

    if passed_required == total_required:
        print("\n[+] All required components are installed!")
        print("[*] Phase 3.5 is ready for use.")

        if passed_optional < total_optional:
            print("\n[!] Some optional tools are missing:")
            print("    - interactsh-client: Required for OOB callback detection")
            print("    Install with: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")

        return 0
    else:
        print("\n[-] Some required components are missing!")
        print("[*] Please run: ./scripts/setup_phase35.sh")
        return 1


def test_basic_functionality():
    """Run basic functionality tests."""
    print("\n" + "=" * 60)
    print("BASIC FUNCTIONALITY TEST")
    print("=" * 60)

    try:
        # Test SSRF Tester instantiation
        print("\n[*] Testing SSRF Tester...")
        from wrappers.advanced.ssrf_tester import SSRFTester
        tester = SSRFTester()
        print(f"  [+] SSRFTester instantiated: tool_name={tester.tool_name}")

        # Test XXE Injector instantiation
        print("\n[*] Testing XXE Injector...")
        from wrappers.advanced.xxe_injector import XXEInjector
        injector = XXEInjector()
        print(f"  [+] XXEInjector instantiated: tool_name={injector.tool_name}")

        # Test HTTP Smuggler instantiation
        print("\n[*] Testing HTTP Smuggler...")
        from wrappers.advanced.http_smuggler import HTTPSmuggler
        smuggler = HTTPSmuggler()
        print(f"  [+] HTTPSmuggler instantiated: tool_name={smuggler.tool_name}")

        # Test Race Condition Tester instantiation
        print("\n[*] Testing Race Condition Tester...")
        from wrappers.advanced.race_condition import RaceConditionTester
        race = RaceConditionTester()
        print(f"  [+] RaceConditionTester instantiated: tool_name={race.tool_name}")

        # Test CORS Tester instantiation
        print("\n[*] Testing CORS Tester...")
        from wrappers.advanced.cors_tester import CORSTester
        cors = CORSTester()
        print(f"  [+] CORSTester instantiated: tool_name={cors.tool_name}")

        # Test File Upload Bypass instantiation
        print("\n[*] Testing File Upload Bypass...")
        from wrappers.advanced.file_upload_bypass import FileUploadBypass
        upload = FileUploadBypass()
        print(f"  [+] FileUploadBypass instantiated: tool_name={upload.tool_name}")

        # Test OOB Callback utility
        print("\n[*] Testing OOB Callback utility...")
        from utils.oob_callback import OOBCallback, SimpleWebhookServer
        print("  [+] OOBCallback class imported")
        print("  [+] SimpleWebhookServer class imported")

        # Test Workflow
        print("\n[*] Testing Advanced Vulns Workflow...")
        from workflows.advanced_vulns import AdvancedVulnWorkflow
        print("  [+] AdvancedVulnWorkflow class imported")

        print("\n[+] All functionality tests passed!")
        return 0

    except Exception as e:
        print(f"\n[-] Functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Validate Phase 3.5 installation")
    parser.add_argument("--test", action="store_true", help="Run functionality tests")
    args = parser.parse_args()

    validation_result = validate_phase35()

    if args.test:
        test_result = test_basic_functionality()
        sys.exit(max(validation_result, test_result))
    else:
        sys.exit(validation_result)
