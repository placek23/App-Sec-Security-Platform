#!/usr/bin/env python3
"""
Phase 5 Validation Script - Authentication & Authorization Testing
Validates that all Phase 5 components are properly installed and configured.
"""

import sys
import subprocess
import importlib
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def print_header(text: str):
    """Print section header"""
    print(f"\n{'='*60}")
    print(text)
    print('='*60)


def check_python_module(module_name: str, package_name: str = None) -> bool:
    """Check if a Python module is importable"""
    package_name = package_name or module_name
    try:
        importlib.import_module(module_name)
        print(f"  [+] {package_name}: OK")
        return True
    except ImportError as e:
        print(f"  [-] {package_name}: MISSING ({e})")
        return False


def check_tool_binary(binary: str, version_flag: str = '--version') -> bool:
    """Check if an external tool binary exists"""
    try:
        result = subprocess.run(
            [binary, version_flag],
            capture_output=True,
            timeout=10
        )
        print(f"  [+] {binary}: OK")
        return True
    except FileNotFoundError:
        print(f"  [-] {binary}: NOT FOUND")
        return False
    except subprocess.TimeoutExpired:
        print(f"  [!] {binary}: TIMEOUT (may still work)")
        return True
    except Exception as e:
        # Try with --help as fallback
        try:
            result = subprocess.run(
                [binary, '--help'],
                capture_output=True,
                timeout=10
            )
            print(f"  [+] {binary}: OK (via --help)")
            return True
        except:
            print(f"  [-] {binary}: ERROR ({e})")
            return False


def check_wrapper_module(module_path: str, class_name: str) -> bool:
    """Check if a wrapper module and class are importable"""
    try:
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        print(f"  [+] {class_name}: OK")
        return True
    except ImportError as e:
        print(f"  [-] {class_name}: IMPORT FAILED ({e})")
        return False
    except AttributeError as e:
        print(f"  [-] {class_name}: CLASS NOT FOUND ({e})")
        return False


def check_file_exists(file_path: str, description: str) -> bool:
    """Check if a file exists"""
    path = Path(__file__).parent.parent / file_path
    if path.exists():
        print(f"  [+] {description}: OK")
        return True
    else:
        print(f"  [-] {description}: NOT FOUND ({path})")
        return False


def check_directory_exists(dir_path: str, description: str) -> bool:
    """Check if a directory exists"""
    path = Path(__file__).parent.parent / dir_path
    if path.is_dir():
        print(f"  [+] {description}: OK")
        return True
    else:
        print(f"  [-] {description}: NOT FOUND ({path})")
        return False


def validate_python_dependencies() -> int:
    """Validate Python dependencies"""
    print_header("Python Dependencies")

    failures = 0

    # Core dependencies
    if not check_python_module("requests"): failures += 1
    if not check_python_module("urllib3"): failures += 1
    if not check_python_module("jwt", "pyjwt"): failures += 1

    return failures


def validate_external_tools() -> int:
    """Validate external tools"""
    print_header("External Tools")

    failures = 0

    # Hydra (optional but recommended)
    if not check_tool_binary("hydra", "-h"):
        print("    Note: Hydra is optional but recommended for brute force testing")

    return failures


def validate_wrapper_modules() -> int:
    """Validate wrapper modules"""
    print_header("Wrapper Modules")

    failures = 0

    # Auth wrappers
    if not check_wrapper_module("wrappers.auth.auth_bypass", "AuthBypassTester"):
        failures += 1
    if not check_wrapper_module("wrappers.auth.idor_tester", "IDORTester"):
        failures += 1
    if not check_wrapper_module("wrappers.auth.jwt_attacks", "JWTAttacksTester"):
        failures += 1
    if not check_wrapper_module("wrappers.auth.hydra_wrapper", "HydraWrapper"):
        failures += 1
    if not check_wrapper_module("wrappers.auth.privilege_escalation", "PrivilegeEscalationTester"):
        failures += 1

    # Check __init__.py exports
    try:
        from wrappers.auth import (
            AuthBypassTester,
            IDORTester,
            JWTAttacksTester,
            HydraWrapper,
            PrivilegeEscalationTester
        )
        print(f"  [+] wrappers.auth __init__.py exports: OK")
    except ImportError as e:
        print(f"  [-] wrappers.auth __init__.py exports: FAILED ({e})")
        failures += 1

    return failures


def validate_workflow() -> int:
    """Validate workflow module"""
    print_header("Workflow")

    failures = 0

    if not check_wrapper_module("workflows.auth_testing", "AuthTestingWorkflow"):
        failures += 1

    return failures


def validate_config_files() -> int:
    """Validate configuration files"""
    print_header("Configuration Files")

    failures = 0

    # tools.json
    if not check_file_exists("config/tools.json", "tools.json"):
        failures += 1
    else:
        # Validate auth section in tools.json
        import json
        config_path = Path(__file__).parent.parent / "config/tools.json"
        try:
            with open(config_path) as f:
                config = json.load(f)

            auth_tools = config.get("tools", {}).get("auth", {})
            expected_tools = ["auth_bypass", "idor_tester", "jwt_attacks", "hydra", "privilege_escalation"]

            for tool in expected_tools:
                if tool in auth_tools:
                    print(f"    [+] tools.json auth.{tool}: OK")
                else:
                    print(f"    [-] tools.json auth.{tool}: MISSING")
                    failures += 1
        except Exception as e:
            print(f"  [-] tools.json validation failed: {e}")
            failures += 1

    return failures


def validate_payload_files() -> int:
    """Validate payload files"""
    print_header("Payload Files")

    failures = 0

    # Directories
    if not check_directory_exists("config/payloads/auth", "auth payloads directory"):
        failures += 1
    if not check_directory_exists("config/payloads/auth/bypass", "bypass payloads directory"):
        failures += 1
    if not check_directory_exists("config/payloads/auth/jwt", "jwt payloads directory"):
        failures += 1
    if not check_directory_exists("config/payloads/auth/credentials", "credentials payloads directory"):
        failures += 1

    # Files
    if not check_file_exists("config/payloads/auth/bypass/sql_bypass.txt", "SQL bypass payloads"):
        failures += 1
    if not check_file_exists("config/payloads/auth/bypass/header_bypass.txt", "Header bypass payloads"):
        failures += 1
    if not check_file_exists("config/payloads/auth/jwt/common_secrets.txt", "JWT common secrets"):
        failures += 1
    if not check_file_exists("config/payloads/auth/credentials/default_credentials.txt", "Default credentials"):
        failures += 1

    return failures


def validate_wordlists() -> int:
    """Validate wordlists"""
    print_header("Wordlists")

    failures = 0

    if not check_file_exists("config/wordlists/10k-most-common.txt", "10k passwords"):
        failures += 1
    if not check_file_exists("config/wordlists/top-usernames-shortlist.txt", "Top usernames"):
        failures += 1

    return failures


def run_basic_tests() -> int:
    """Run basic functionality tests"""
    print_header("Basic Functionality Tests")

    failures = 0

    # Test AuthBypassTester instantiation
    try:
        from wrappers.auth import AuthBypassTester
        tester = AuthBypassTester()
        print(f"  [+] AuthBypassTester instantiation: OK")
    except Exception as e:
        print(f"  [-] AuthBypassTester instantiation: FAILED ({e})")
        failures += 1

    # Test IDORTester instantiation
    try:
        from wrappers.auth import IDORTester
        tester = IDORTester()
        print(f"  [+] IDORTester instantiation: OK")
    except Exception as e:
        print(f"  [-] IDORTester instantiation: FAILED ({e})")
        failures += 1

    # Test JWTAttacksTester instantiation and decode
    try:
        from wrappers.auth import JWTAttacksTester
        tester = JWTAttacksTester()
        # Test JWT decode
        test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        decoded = tester._decode_jwt(test_token)
        if "error" not in decoded and decoded.get("payload", {}).get("name") == "John Doe":
            print(f"  [+] JWTAttacksTester JWT decode: OK")
        else:
            print(f"  [-] JWTAttacksTester JWT decode: FAILED")
            failures += 1
    except Exception as e:
        print(f"  [-] JWTAttacksTester instantiation: FAILED ({e})")
        failures += 1

    # Test PrivilegeEscalationTester instantiation
    try:
        from wrappers.auth import PrivilegeEscalationTester
        tester = PrivilegeEscalationTester()
        print(f"  [+] PrivilegeEscalationTester instantiation: OK")
    except Exception as e:
        print(f"  [-] PrivilegeEscalationTester instantiation: FAILED ({e})")
        failures += 1

    # Test AuthTestingWorkflow instantiation
    try:
        from workflows.auth_testing import AuthTestingWorkflow
        workflow = AuthTestingWorkflow("https://example.com", "/tmp/test_output")
        print(f"  [+] AuthTestingWorkflow instantiation: OK")
    except Exception as e:
        print(f"  [-] AuthTestingWorkflow instantiation: FAILED ({e})")
        failures += 1

    return failures


def main():
    """Main validation function"""
    print("\n" + "="*60)
    print("PHASE 5 VALIDATION: Authentication & Authorization Testing")
    print("="*60)

    total_failures = 0

    total_failures += validate_python_dependencies()
    total_failures += validate_external_tools()
    total_failures += validate_wrapper_modules()
    total_failures += validate_workflow()
    total_failures += validate_config_files()
    total_failures += validate_payload_files()
    total_failures += validate_wordlists()
    total_failures += run_basic_tests()

    print_header("VALIDATION SUMMARY")

    if total_failures == 0:
        print("\n  ✓ All Phase 5 components validated successfully!")
        print("\n  Phase 5 is ready to use.")
        return 0
    else:
        print(f"\n  ✗ {total_failures} validation check(s) failed.")
        print("\n  Run ./scripts/setup_phase5.sh to install missing components.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
