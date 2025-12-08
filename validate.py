#!/usr/bin/env python3
"""
Platform validation script - tests all imports and basic functionality
"""
import sys
from pathlib import Path

# Add platform to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test all imports work correctly"""
    print("Testing imports...")
    
    errors = []
    
    # Test utils
    try:
        from utils import BaseToolWrapper, OutputParser, Reporter, RateLimiter
        print("  ✓ utils")
    except Exception as e:
        errors.append(f"utils: {e}")
        print(f"  ✗ utils: {e}")
    
    # Test recon wrappers
    try:
        from wrappers.recon import SubfinderWrapper, AmassWrapper, HttpxWrapper, KatanaWrapper, GauWrapper
        print("  ✓ wrappers.recon")
    except Exception as e:
        errors.append(f"wrappers.recon: {e}")
        print(f"  ✗ wrappers.recon: {e}")
    
    # Test discovery wrappers
    try:
        from wrappers.discovery import FfufWrapper, FeroxbusterWrapper, ArjunWrapper, ParamspiderWrapper
        print("  ✓ wrappers.discovery")
    except Exception as e:
        errors.append(f"wrappers.discovery: {e}")
        print(f"  ✗ wrappers.discovery: {e}")
    
    # Test scanning wrappers
    try:
        from wrappers.scanning import NucleiWrapper, Wafw00fWrapper, WhatwebWrapper
        print("  ✓ wrappers.scanning")
    except Exception as e:
        errors.append(f"wrappers.scanning: {e}")
        print(f"  ✗ wrappers.scanning: {e}")
    
    # Test injection wrappers
    try:
        from wrappers.injection import SqlmapWrapper, DalfoxWrapper, CommixWrapper, TplmapWrapper
        print("  ✓ wrappers.injection")
    except Exception as e:
        errors.append(f"wrappers.injection: {e}")
        print(f"  ✗ wrappers.injection: {e}")
    
    # Test auth wrappers
    try:
        from wrappers.auth import JwtToolWrapper, SubjackWrapper
        print("  ✓ wrappers.auth")
    except Exception as e:
        errors.append(f"wrappers.auth: {e}")
        print(f"  ✗ wrappers.auth: {e}")
    
    # Test api wrappers
    try:
        from wrappers.api import GraphqlVoyagerWrapper, TestsslWrapper
        print("  ✓ wrappers.api")
    except Exception as e:
        errors.append(f"wrappers.api: {e}")
        print(f"  ✗ wrappers.api: {e}")
    
    # Test workflows
    try:
        from workflows import FullReconWorkflow, VulnScanWorkflow, InjectionTestWorkflow
        print("  ✓ workflows")
    except Exception as e:
        errors.append(f"workflows: {e}")
        print(f"  ✗ workflows: {e}")
    
    # Test agents
    try:
        from agents import BountyHunterAgent, AgentConfig, VulnScannerAgent, ScanConfig
        print("  ✓ agents")
    except Exception as e:
        errors.append(f"agents: {e}")
        print(f"  ✗ agents: {e}")
    
    return errors


def test_wrapper_instantiation():
    """Test wrapper classes can be instantiated"""
    print("\nTesting wrapper instantiation...")
    
    from wrappers.recon import SubfinderWrapper
    from wrappers.scanning import NucleiWrapper
    from wrappers.injection import SqlmapWrapper
    
    try:
        sf = SubfinderWrapper()
        print(f"  ✓ SubfinderWrapper (tool_name: {sf.tool_name})")
        
        nuc = NucleiWrapper()
        print(f"  ✓ NucleiWrapper (tool_name: {nuc.tool_name})")
        
        sql = SqlmapWrapper()
        print(f"  ✓ SqlmapWrapper (tool_name: {sql.tool_name})")
        
        return []
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return [str(e)]


def test_output_parser():
    """Test output parser functionality"""
    print("\nTesting output parser...")
    
    from utils.output_parser import OutputParser, Finding, Severity, Subdomain
    
    try:
        # Test Finding creation
        finding = Finding(
            tool="test",
            target="example.com",
            finding_type="test",
            title="Test Finding",
            severity=Severity.HIGH
        )
        print(f"  ✓ Finding created: {finding.title} ({finding.severity.value})")
        
        # Test Subdomain creation
        sub = Subdomain(domain="test.example.com", source="test")
        print(f"  ✓ Subdomain created: {sub.domain}")
        
        # Test to_dict
        finding_dict = finding.to_dict()
        print(f"  ✓ Finding.to_dict() works")
        
        return []
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return [str(e)]


def test_reporter():
    """Test reporter functionality"""
    print("\nTesting reporter...")
    
    from utils.reporter import Reporter, ReportConfig
    
    try:
        config = ReportConfig(
            title="Test Report",
            target="example.com",
            tester="Test"
        )
        reporter = Reporter(config)
        print(f"  ✓ Reporter created")
        
        # Add a test finding
        reporter.add_findings([{
            "title": "Test Finding",
            "severity": "high",
            "url": "https://example.com",
            "description": "Test description"
        }])
        print(f"  ✓ Finding added")
        
        return []
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return [str(e)]


def test_rate_limiter():
    """Test rate limiter functionality"""
    print("\nTesting rate limiter...")
    
    from utils.rate_limiter import RateLimiter, AdaptiveRateLimiter
    
    try:
        rl = RateLimiter(requests_per_second=10)
        print(f"  ✓ RateLimiter created (10 req/s)")
        
        arl = AdaptiveRateLimiter(initial_rate=10)
        print(f"  ✓ AdaptiveRateLimiter created")
        
        return []
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return [str(e)]


def main():
    print("=" * 60)
    print("AppSec Bounty Platform - Validation")
    print("=" * 60)
    
    all_errors = []
    
    # Run tests
    all_errors.extend(test_imports())
    all_errors.extend(test_wrapper_instantiation())
    all_errors.extend(test_output_parser())
    all_errors.extend(test_reporter())
    all_errors.extend(test_rate_limiter())
    
    # Summary
    print("\n" + "=" * 60)
    if all_errors:
        print(f"❌ VALIDATION FAILED - {len(all_errors)} errors")
        for err in all_errors:
            print(f"   - {err}")
        return 1
    else:
        print("✅ VALIDATION PASSED - All tests successful!")
        print("\nPlatform is ready to use:")
        print("  python agents/bounty_hunter.py --target example.com")
        print("  python workflows/full_recon.py --target example.com")
        return 0


if __name__ == "__main__":
    sys.exit(main())
