#!/usr/bin/env python3
"""
Phase 6: Reporting & Integration Enhancement - Validation Script
Validates that all Phase 6 components are properly installed and functional.
"""

import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'


def print_header(text):
    print(f"\n{BOLD}{BLUE}{'=' * 60}{RESET}")
    print(f"{BOLD}{BLUE}{text}{RESET}")
    print(f"{BOLD}{BLUE}{'=' * 60}{RESET}\n")


def print_ok(text):
    print(f"  {GREEN}[OK]{RESET} {text}")


def print_fail(text):
    print(f"  {RED}[FAIL]{RESET} {text}")


def print_warn(text):
    print(f"  {YELLOW}[WARN]{RESET} {text}")


def print_info(text):
    print(f"  {BLUE}[INFO]{RESET} {text}")


def check_import(module_name, package_name=None):
    """Check if a module can be imported"""
    try:
        __import__(module_name)
        print_ok(f"{package_name or module_name}")
        return True
    except ImportError as e:
        print_fail(f"{package_name or module_name}: {e}")
        return False


def validate_python_dependencies():
    """Validate Python package dependencies"""
    print_header("Validating Python Dependencies")

    results = []

    # Core dependencies
    results.append(check_import('reportlab', 'ReportLab (PDF generation)'))
    results.append(check_import('sqlalchemy', 'SQLAlchemy (Database ORM)'))
    results.append(check_import('alembic', 'Alembic (Database migrations)'))
    results.append(check_import('jinja2', 'Jinja2 (Templating)'))
    results.append(check_import('markdown', 'Markdown'))

    # Optional dependencies
    try:
        import weasyprint
        print_ok("WeasyPrint (HTML to PDF) - optional")
        results.append(True)
    except (ImportError, OSError) as e:
        print_warn(f"WeasyPrint not available (optional): {type(e).__name__}")
        results.append(True)  # Optional, so don't fail

    # API framework (optional)
    try:
        import fastapi
        print_ok("FastAPI (optional)")
    except ImportError:
        print_warn("FastAPI not available (optional)")

    try:
        import uvicorn
        print_ok("Uvicorn (optional)")
    except ImportError:
        print_warn("Uvicorn not available (optional)")

    return all(results)


def validate_database_module():
    """Validate database module"""
    print_header("Validating Database Module")

    results = []

    # Check database models
    try:
        from database.models import (
            Base, Target, Scan, Finding, Subdomain, Endpoint,
            Session, Report, SeverityLevel, ScanStatus, ScanType
        )
        print_ok("Database models imported successfully")
        results.append(True)
    except ImportError as e:
        print_fail(f"Database models: {e}")
        results.append(False)

    # Check database manager
    try:
        from database.manager import DatabaseManager
        print_ok("DatabaseManager imported successfully")
        results.append(True)
    except ImportError as e:
        print_fail(f"DatabaseManager: {e}")
        results.append(False)

    # Test database creation
    try:
        from database.manager import DatabaseManager
        import tempfile

        with tempfile.NamedTemporaryFile(suffix='.db', delete=True) as f:
            db_path = f"sqlite:///{f.name}"
            manager = DatabaseManager(db_path)

            # Test basic operations
            target = manager.create_target(
                name='Test Target',
                domain='test.example.com',
                description='Test target for validation'
            )

            if target and target.get('id'):
                print_ok("Database CRUD operations working")
                results.append(True)
            else:
                print_fail("Database CRUD operations failed")
                results.append(False)

    except Exception as e:
        print_fail(f"Database operations: {e}")
        results.append(False)

    return all(results)


def validate_reporting_module():
    """Validate reporting modules"""
    print_header("Validating Reporting Modules")

    results = []

    # Check advanced reporter
    try:
        from utils.advanced_reporter import (
            AdvancedReporter, EnhancedFinding, CVSSVector,
            VULNERABILITY_MAPPINGS
        )
        print_ok("AdvancedReporter imported successfully")
        results.append(True)

        # Test CVSS calculation
        cvss = CVSSVector(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            scope='U',
            confidentiality_impact='H',
            integrity_impact='H',
            availability_impact='H'
        )
        score, rating = cvss.calculate_score()
        if score > 0:
            print_ok(f"CVSS calculation working (test score: {score})")
            results.append(True)
        else:
            print_fail("CVSS calculation returned 0")
            results.append(False)

    except ImportError as e:
        print_fail(f"AdvancedReporter: {e}")
        results.append(False)

    # Check PDF generator
    try:
        from utils.pdf_generator import PDFReportGenerator
        print_ok("PDFReportGenerator imported successfully")
        results.append(True)
    except ImportError as e:
        print_fail(f"PDFReportGenerator: {e}")
        results.append(False)

    # Check original reporter
    try:
        from utils.reporter import Reporter, ReportConfig
        print_ok("Original Reporter still functional")
        results.append(True)
    except ImportError as e:
        print_warn(f"Original Reporter: {e}")
        results.append(True)  # Not critical

    return all(results)


def validate_analytics_module():
    """Validate analytics module"""
    print_header("Validating Analytics Module")

    results = []

    try:
        from utils.analytics import (
            SecurityAnalytics, ComparisonReport,
            TrendDataPoint, AnalyticsSummary
        )
        print_ok("SecurityAnalytics imported successfully")
        results.append(True)

        # Test analytics
        analytics = SecurityAnalytics()

        sample_scans = [{
            'id': 1,
            'created_at': '2024-01-01T00:00:00',
            'findings_count': 5,
            'critical_count': 1,
            'high_count': 2,
            'risk_score': 75.0
        }]

        sample_findings = [
            {'severity': 'critical', 'finding_type': 'sqli'},
            {'severity': 'high', 'finding_type': 'xss'}
        ]

        summary = analytics.analyze_scans(sample_scans, sample_findings)
        if summary and summary.total_findings > 0:
            print_ok("Analytics analysis working")
            results.append(True)
        else:
            print_fail("Analytics analysis failed")
            results.append(False)

    except ImportError as e:
        print_fail(f"SecurityAnalytics: {e}")
        results.append(False)

    return all(results)


def validate_aggregator_module():
    """Validate report aggregator module"""
    print_header("Validating Report Aggregator")

    results = []

    try:
        from utils.report_aggregator import (
            ReportAggregator, TargetSummary, AggregatedReport
        )
        print_ok("ReportAggregator imported successfully")
        results.append(True)

        # Test aggregation
        aggregator = ReportAggregator()
        aggregator.add_scan_results(
            target='test.com',
            scan={'id': 1},
            findings=[{'title': 'Test', 'severity': 'high'}]
        )

        report = aggregator.generate_aggregated_report()
        if report and report.targets_count > 0:
            print_ok("Report aggregation working")
            results.append(True)
        else:
            print_fail("Report aggregation failed")
            results.append(False)

    except ImportError as e:
        print_fail(f"ReportAggregator: {e}")
        results.append(False)

    return all(results)


def validate_templates():
    """Validate report templates"""
    print_header("Validating Report Templates")

    results = []

    template_dir = PROJECT_ROOT / 'templates' / 'reports'

    if template_dir.exists():
        print_ok("Templates directory exists")
        results.append(True)

        # Check for expected templates
        expected_templates = ['report.html', 'executive_summary.html']
        for template in expected_templates:
            template_path = template_dir / template
            if template_path.exists():
                print_ok(f"Template: {template}")
                results.append(True)
            else:
                print_warn(f"Template not found: {template}")
                results.append(True)  # Not critical
    else:
        print_warn("Templates directory not found")
        results.append(True)  # Will be created on first use

    return all(results)


def validate_directory_structure():
    """Validate directory structure"""
    print_header("Validating Directory Structure")

    results = []

    directories = [
        'database',
        'utils',
        'templates/reports',
        'output',
    ]

    for dir_path in directories:
        full_path = PROJECT_ROOT / dir_path
        if full_path.exists():
            print_ok(f"Directory: {dir_path}")
            results.append(True)
        else:
            print_warn(f"Directory not found (will be created): {dir_path}")
            results.append(True)  # Will be created

    return all(results)


def run_integration_test():
    """Run a simple integration test"""
    print_header("Running Integration Test")

    try:
        import tempfile
        from utils.advanced_reporter import AdvancedReporter

        # Create reporter
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = AdvancedReporter(output_dir=tmpdir)
            reporter.set_metadata(
                title='Validation Test Report',
                target='validation.test',
                tester='Phase 6 Validator'
            )

            # Add test finding
            reporter.add_finding(
                title='Test SQL Injection',
                severity='high',
                finding_type='sqli',
                tool='validator',
                url='https://test.com/login',
                description='Test finding for validation'
            )

            # Generate reports
            json_path = reporter.export_json('test_report.json')
            html_path = reporter.export_html('test_report.html')
            md_path = reporter.export_markdown('test_report.md')

            if os.path.exists(json_path) and os.path.exists(html_path):
                print_ok("Integration test passed - reports generated successfully")
                return True
            else:
                print_fail("Integration test failed - reports not generated")
                return False

    except Exception as e:
        print_fail(f"Integration test failed: {e}")
        return False


def main():
    """Main validation function"""
    print(f"\n{BOLD}Phase 6: Reporting & Integration Enhancement{RESET}")
    print(f"{BOLD}Validation Script{RESET}")
    print(f"{'=' * 60}")

    all_passed = True

    # Run all validations
    all_passed &= validate_python_dependencies()
    all_passed &= validate_database_module()
    all_passed &= validate_reporting_module()
    all_passed &= validate_analytics_module()
    all_passed &= validate_aggregator_module()
    all_passed &= validate_templates()
    all_passed &= validate_directory_structure()
    all_passed &= run_integration_test()

    # Print summary
    print_header("Validation Summary")

    if all_passed:
        print(f"{GREEN}{BOLD}All Phase 6 validations passed!{RESET}")
        print("\nPhase 6 is ready for use.")
        print("\nKey features available:")
        print("  - PDF report generation (ReportLab)")
        print("  - Database storage (SQLAlchemy)")
        print("  - Advanced reporting with CVSS scoring")
        print("  - Analytics and trend analysis")
        print("  - Multi-target report aggregation")
        print("  - Jinja2 report templates")
        return 0
    else:
        print(f"{RED}{BOLD}Some validations failed.{RESET}")
        print("\nPlease run the setup script:")
        print("  ./scripts/setup_phase6.sh")
        return 1


if __name__ == '__main__':
    sys.exit(main())
