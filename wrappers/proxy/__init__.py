"""
Proxy integration wrappers for manual testing support.

This module provides wrappers for:
- OWASP ZAP integration
- HTTP request building and manipulation
- Session and cookie management
"""

from .zap_integration import ZAPIntegration
from .request_builder import RequestBuilder
from .session_manager import SessionManager

__all__ = [
    'ZAPIntegration',
    'RequestBuilder',
    'SessionManager',
]
