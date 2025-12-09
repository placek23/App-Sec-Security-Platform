"""
Advanced Web Vulnerability Testing Wrappers

Phase 3.5 implementation for testing advanced web vulnerabilities:
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- HTTP Request Smuggling
- Race Conditions
- CORS Misconfigurations
- File Upload Bypass
"""

from .ssrf_tester import SSRFTester
from .xxe_injector import XXEInjector
from .http_smuggler import HTTPSmuggler
from .race_condition import RaceConditionTester
from .cors_tester import CORSTester
from .file_upload_bypass import FileUploadBypass

__all__ = [
    'SSRFTester',
    'XXEInjector',
    'HTTPSmuggler',
    'RaceConditionTester',
    'CORSTester',
    'FileUploadBypass',
]
