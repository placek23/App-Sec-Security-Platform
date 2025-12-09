# Auth wrappers - Phase 5: Authentication & Authorization Testing
from .jwt_tool import JwtToolWrapper
from .subjack import SubjackWrapper
from .auth_bypass import AuthBypassTester
from .idor_tester import IDORTester
from .jwt_attacks import JWTAttacksTester
from .hydra_wrapper import HydraWrapper
from .privilege_escalation import PrivilegeEscalationTester

__all__ = [
    'JwtToolWrapper',
    'SubjackWrapper',
    'AuthBypassTester',
    'IDORTester',
    'JWTAttacksTester',
    'HydraWrapper',
    'PrivilegeEscalationTester'
]
