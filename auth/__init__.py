"""
API Hunter Authentication Module

This module provides comprehensive authentication and authorization testing capabilities
for API security testing, including JWT analysis, OAuth testing, and session management.
"""

from .auth_manager import AuthManager
from .jwt_analyzer import JWTAnalyzer, JWTVulnerability
from .oauth_tester import OAuthTester, OAuthFlow
from .api_key_manager import APIKeyManager
from .session_analyzer import SessionAnalyzer
from .auth_bypass import AuthBypassTester
from .token_bruteforcer import TokenBruteforcer

__all__ = [
    'AuthManager',
    'JWTAnalyzer',
    'JWTVulnerability',
    'OAuthTester',
    'OAuthFlow',
    'APIKeyManager',
    'SessionAnalyzer',
    'AuthBypassTester',
    'TokenBruteforcer'
]
