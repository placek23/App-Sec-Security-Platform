#!/usr/bin/env python3
"""
Phase 1: Web Discovery & Reconnaissance - Test Script
Tests all Phase 1 wrappers and tools
"""
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def check_tool_installed(tool_name: str, check_cmd: list) -> bool:
    """Check if a tool is installed and accessible"""
    import subprocess
    try:
        result = subprocess.run(check_cmd, capture_output=True, timeout=10)
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        return False


def test_wrapper_import(wrapper_name: str, module_path: str) -> bool:
    """Test if a wrapper can be imported"""
    try:
        exec(f"from {module_path} import {wrapper_name}")
        return True
    except ImportError as e:
        console.print(f"  [red]Import error: {e}[/red]")
        return False


def main():
    console.print(Panel.fit(
        "[bold blue]Phase 1: Web Discovery & Reconnaissance[/bold blue]\n"
        "[dim]Testing tool installations and wrapper imports[/dim]",
        title="Test Suite"
    ))

    # Test tool installations
    console.print("\n[bold]Checking Tool Installations[/bold]\n")

    tools_table = Table(show_header=True)
    tools_table.add_column("Tool", style="cyan")
    tools_table.add_column("Status", justify="center")
    tools_table.add_column("Notes")

    tools = [
        ("gobuster", ["gobuster", "version"]),
        ("dirsearch", ["dirsearch", "--help"]),
        ("gowitness", ["gowitness", "--help"]),
        ("subjs", ["subjs", "--help"]),
        ("x8", ["x8", "--help"]),
    ]

    for tool_name, check_cmd in tools:
        if check_tool_installed(tool_name, check_cmd):
            tools_table.add_row(tool_name, "[green]✓ Installed[/green]", "")
        else:
            tools_table.add_row(tool_name, "[red]✗ Not Found[/red]", "Run setup_phase1.sh")

    console.print(tools_table)

    # Test Python tools
    console.print("\n[bold]Checking Python Tools[/bold]\n")

    python_tools = [
        ("LinkFinder", "~/tools/LinkFinder/linkfinder.py"),
        ("SecretFinder", "~/tools/SecretFinder/SecretFinder.py"),
    ]

    py_table = Table(show_header=True)
    py_table.add_column("Tool", style="cyan")
    py_table.add_column("Status", justify="center")
    py_table.add_column("Path")

    for tool_name, tool_path in python_tools:
        expanded_path = os.path.expanduser(tool_path)
        if os.path.exists(expanded_path):
            py_table.add_row(tool_name, "[green]✓ Found[/green]", expanded_path)
        else:
            py_table.add_row(tool_name, "[red]✗ Not Found[/red]", tool_path)

    console.print(py_table)

    # Test wrapper imports
    console.print("\n[bold]Testing Wrapper Imports[/bold]\n")

    wrappers = [
        ("GobusterWrapper", "wrappers.discovery.gobuster"),
        ("DirsearchWrapper", "wrappers.discovery.dirsearch_wrapper"),
        ("LinkFinderWrapper", "wrappers.discovery.linkfinder"),
        ("SecretFinderWrapper", "wrappers.discovery.secretfinder"),
        ("GoWitnessWrapper", "wrappers.discovery.gowitness"),
        ("FfufWrapper", "wrappers.discovery.ffuf"),
    ]

    wrapper_table = Table(show_header=True)
    wrapper_table.add_column("Wrapper", style="cyan")
    wrapper_table.add_column("Status", justify="center")

    for wrapper_name, module_path in wrappers:
        if test_wrapper_import(wrapper_name, module_path):
            wrapper_table.add_row(wrapper_name, "[green]✓ OK[/green]")
        else:
            wrapper_table.add_row(wrapper_name, "[red]✗ Failed[/red]")

    console.print(wrapper_table)

    # Check wordlists
    console.print("\n[bold]Checking Wordlists[/bold]\n")

    wordlist_dir = Path(__file__).parent.parent / "config" / "wordlists"

    wordlists = [
        "common.txt",
        "medium.txt",
    ]

    wl_table = Table(show_header=True)
    wl_table.add_column("Wordlist", style="cyan")
    wl_table.add_column("Status", justify="center")
    wl_table.add_column("Size")

    for wl in wordlists:
        wl_path = wordlist_dir / wl
        if wl_path.exists():
            size = wl_path.stat().st_size
            size_str = f"{size / 1024:.1f} KB" if size < 1024*1024 else f"{size / (1024*1024):.1f} MB"
            wl_table.add_row(wl, "[green]✓ Found[/green]", size_str)
        else:
            wl_table.add_row(wl, "[red]✗ Not Found[/red]", "-")

    console.print(wl_table)

    # Print example commands
    console.print("\n[bold]Example Commands[/bold]\n")

    examples = """
[cyan]# Directory brute forcing with Gobuster[/cyan]
python wrappers/discovery/gobuster.py -u https://example.com -w config/wordlists/common.txt

[cyan]# Path discovery with Dirsearch[/cyan]
python wrappers/discovery/dirsearch_wrapper.py -u https://example.com -e php,html

[cyan]# Find endpoints in JavaScript[/cyan]
python wrappers/discovery/linkfinder.py -i https://example.com/app.js

[cyan]# Find secrets in JavaScript[/cyan]
python wrappers/discovery/secretfinder.py -i https://example.com/app.js

[cyan]# Take screenshots[/cyan]
python wrappers/discovery/gowitness.py -u https://example.com -P ./screenshots

[cyan]# Fuzz with FFuf[/cyan]
python wrappers/discovery/ffuf.py -u https://example.com/FUZZ -w config/wordlists/common.txt
"""
    console.print(Panel(examples, title="Usage Examples", expand=False))

    console.print("\n[green]Phase 1 test complete![/green]\n")


if __name__ == "__main__":
    main()
