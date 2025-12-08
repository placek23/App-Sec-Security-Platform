"""
Core utilities for AppSec Bounty Platform
"""
from .base_wrapper import (
    BaseToolWrapper,
    ReconTool,
    DiscoveryTool,
    ScanningTool,
    InjectionTool,
    AuthTool,
    APITool,
    ProxyTool
)
from .output_parser import OutputParser, Severity, Finding, Subdomain, Endpoint
from .reporter import Reporter
from .rate_limiter import RateLimiter, AdaptiveRateLimiter, DomainRateLimiter
from .nuclei_profiles import (
    NUCLEI_TEMPLATE_PROFILES,
    NUCLEI_TAGS,
    get_profile,
    list_profiles,
    recommend_profile,
    build_nuclei_args,
    get_profile_summary
)
from .template_updater import NucleiTemplateManager
from .encoder import PayloadEncoder, PayloadDecoder

__all__ = [
    # Base classes
    'BaseToolWrapper',
    'ReconTool',
    'DiscoveryTool',
    'ScanningTool',
    'InjectionTool',
    'AuthTool',
    'APITool',
    'ProxyTool',

    # Output parsing
    'OutputParser',
    'Severity',
    'Finding',
    'Subdomain',
    'Endpoint',

    # Reporting
    'Reporter',

    # Rate limiting
    'RateLimiter',
    'AdaptiveRateLimiter',
    'DomainRateLimiter',

    # Nuclei profiles
    'NUCLEI_TEMPLATE_PROFILES',
    'NUCLEI_TAGS',
    'get_profile',
    'list_profiles',
    'recommend_profile',
    'build_nuclei_args',
    'get_profile_summary',

    # Template management
    'NucleiTemplateManager',

    # Encoding utilities (Phase 2)
    'PayloadEncoder',
    'PayloadDecoder',
]
