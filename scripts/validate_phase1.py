#!/usr/bin/env python3
"""
Phase 1 Validation Script
Validates that all Phase 1 components are correctly installed and working
"""
import sys
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def check_command(cmd: list, name: str) -> tuple:
    """Check if a command runs successfully"""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        return True, f"{name} is available"
    except FileNotFoundError:
        return False, f"{name} not found in PATH"
    except subprocess.TimeoutExpired:
        return True, f"{name} is available (timeout during check)"
    except Exception as e:
        return False, f"{name} error: {str(e)}"


def check_python_import(module: str, class_name: str) -> tuple:
    """Check if a Python module can be imported"""
    try:
        exec(f"from {module} import {class_name}")
        return True, f"{class_name} importable"
    except ImportError as e:
        return False, f"Cannot import {class_name}: {e}"
    except Exception as e:
        return False, f"Error importing {class_name}: {e}"


def check_file_exists(path: str, name: str) -> tuple:
    """Check if a file exists"""
    expanded = Path(path).expanduser()
    if expanded.exists():
        return True, f"{name} exists at {expanded}"
    return False, f"{name} not found at {path}"


def main():
    print("=" * 60)
    print("Phase 1: Web Discovery & Reconnaissance - Validation")
    print("=" * 60)
    print()

    all_passed = True
    results = []

    # 1. Check Go Tools
    print("[1/5] Checking Go Tools...")
    go_tools = [
        (["gobuster", "version"], "Gobuster"),
        (["gowitness", "--help"], "GoWitness"),
        (["subjs", "--help"], "Subjs"),
        (["x8", "--help"], "x8"),
    ]

    for cmd, name in go_tools:
        passed, msg = check_command(cmd, name)
        status = "✓" if passed else "✗"
        print(f"  [{status}] {msg}")
        if not passed:
            all_passed = False
        results.append((name, passed, msg))

    # 2. Check Python Tools
    print("\n[2/5] Checking Python Tools...")
    python_tools = [
        (["dirsearch", "--help"], "Dirsearch"),
        (["wfuzz", "--help"], "Wfuzz"),
    ]

    for cmd, name in python_tools:
        passed, msg = check_command(cmd, name)
        status = "✓" if passed else "✗"
        print(f"  [{status}] {msg}")
        if not passed:
            all_passed = False
        results.append((name, passed, msg))

    # 3. Check External Python Scripts
    print("\n[3/5] Checking External Python Scripts...")
    external_scripts = [
        ("~/tools/LinkFinder/linkfinder.py", "LinkFinder"),
        ("~/tools/SecretFinder/SecretFinder.py", "SecretFinder"),
        ("~/tools/git-dumper/git_dumper.py", "Git-Dumper"),
    ]

    for path, name in external_scripts:
        passed, msg = check_file_exists(path, name)
        status = "✓" if passed else "✗"
        print(f"  [{status}] {msg}")
        results.append((name, passed, msg))

    # 4. Check Wrapper Imports
    print("\n[4/5] Checking Wrapper Imports...")
    wrappers = [
        ("wrappers.discovery.gobuster", "GobusterWrapper"),
        ("wrappers.discovery.dirsearch_wrapper", "DirsearchWrapper"),
        ("wrappers.discovery.linkfinder", "LinkFinderWrapper"),
        ("wrappers.discovery.secretfinder", "SecretFinderWrapper"),
        ("wrappers.discovery.gowitness", "GoWitnessWrapper"),
        ("wrappers.discovery.ffuf", "FfufWrapper"),
    ]

    for module, class_name in wrappers:
        passed, msg = check_python_import(module, class_name)
        status = "✓" if passed else "✗"
        print(f"  [{status}] {msg}")
        if not passed:
            all_passed = False
        results.append((class_name, passed, msg))

    # 5. Check Wordlists
    print("\n[5/5] Checking Wordlists...")
    wordlist_dir = Path(__file__).parent.parent / "config" / "wordlists"

    wordlists = [
        (wordlist_dir / "common.txt", "common.txt wordlist"),
        (wordlist_dir / "medium.txt", "medium.txt wordlist"),
    ]

    for path, name in wordlists:
        if path.exists():
            size = path.stat().st_size
            size_str = f"{size/1024:.1f}KB" if size < 1024*1024 else f"{size/(1024*1024):.1f}MB"
            print(f"  [✓] {name} ({size_str})")
            results.append((name, True, f"Found ({size_str})"))
        else:
            print(f"  [✗] {name} not found")
            results.append((name, False, "Not found"))

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    passed_count = sum(1 for _, p, _ in results if p)
    failed_count = len(results) - passed_count

    print(f"\nTotal checks: {len(results)}")
    print(f"  Passed: {passed_count}")
    print(f"  Failed: {failed_count}")

    if failed_count > 0:
        print("\nFailed items:")
        for name, passed, msg in results:
            if not passed:
                print(f"  - {name}: {msg}")

    print("\n" + "=" * 60)

    if all_passed:
        print("✓ All Phase 1 components validated successfully!")
        print("\nYou can now run the web discovery workflow:")
        print("  python workflows/web_discovery.py -t https://example.com -w config/wordlists/common.txt")
    else:
        print("✗ Some components are missing or not working.")
        print("\nTo install missing tools, run:")
        print("  bash scripts/setup_phase1.sh")

    print("=" * 60)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
