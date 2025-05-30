"""
Central Authentication Manager

Coordinates all authentication testing capabilities and manages authentication state
across different testing scenarios.
"""

from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import asyncio
import logging
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from ..core.http_client import HTTPClient
from ..core.models import ScanResult, Vulnerability


class AuthType(Enum):
    """Supported authentication types"""
    JWT = "jwt"
    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    SESSION = "session"
    BASIC = "basic"
    BEARER = "bearer"
    CUSTOM = "custom"


class AuthMethod(Enum):
    """Authentication method locations"""
    HEADER = "header"
    QUERY = "query"
    BODY = "body"
    COOKIE = "cookie"


@dataclass
class AuthCredentials:
    """Authentication credentials container"""
    auth_type: AuthType
    method: AuthMethod
    value: str
    additional_params: Optional[Dict[str, Any]] = None
    expires_at: Optional[str] = None
    refresh_token: Optional[str] = None


class AuthConfig(BaseModel):
    """Authentication configuration"""
    target_url: str = Field(..., description="Target URL for authentication testing")
    credentials: List[AuthCredentials] = Field(default_factory=list)
    test_weak_secrets: bool = Field(default=True)
    test_token_manipulation: bool = Field(default=True)
    test_authorization_bypass: bool = Field(default=True)
    test_session_security: bool = Field(default=True)
    jwt_secret_wordlist: Optional[str] = Field(default=None)
    rate_limit_delay: float = Field(default=1.0)


class AuthManager:
    """Central authentication manager for API security testing"""

    def __init__(self, http_client: HTTPClient, config: AuthConfig):
        self.http_client = http_client
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.active_sessions: Dict[str, AuthCredentials] = {}
        self.discovered_endpoints: List[str] = []

        # Initialize sub-components (will be imported when implemented)
        self._jwt_analyzer = None
        self._oauth_tester = None
        self._api_key_manager = None
        self._session_analyzer = None
        self._auth_bypass_tester = None
        self._token_bruteforcer = None

    async def initialize(self):
        """Initialize authentication testing components"""
        try:
            # Dynamic imports to avoid circular dependencies
            from .jwt_analyzer import JWTAnalyzer
            from .oauth_tester import OAuthTester
            from .api_key_manager import APIKeyManager
            from .session_analyzer import SessionAnalyzer
            from .auth_bypass import AuthBypassTester
            from .token_bruteforcer import TokenBruteforcer

            self._jwt_analyzer = JWTAnalyzer(self.http_client)
            self._oauth_tester = OAuthTester(self.http_client)
            self._api_key_manager = APIKeyManager(self.http_client)
            self._session_analyzer = SessionAnalyzer(self.http_client)
            self._auth_bypass_tester = AuthBypassTester(self.http_client)
            self._token_bruteforcer = TokenBruteforcer(self.http_client)

            self.logger.info("Authentication manager initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize authentication manager: {e}")
            raise

    async def discover_auth_mechanisms(self, target_url: str) -> List[AuthType]:
        """Discover authentication mechanisms used by the API"""
        discovered_auth = []

        try:
            # Test for common authentication endpoints
            auth_endpoints = [
                "/auth/login", "/login", "/api/auth", "/oauth/token",
                "/api/token", "/authenticate", "/signin", "/api/login"
            ]

            base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

            for endpoint in auth_endpoints:
                test_url = f"{base_url}{endpoint}"

                try:
                    response = await self.http_client.get(test_url)

                    # Analyze response headers and content for auth mechanisms
                    if "www-authenticate" in response.headers:
                        auth_header = response.headers["www-authenticate"].lower()
                        if "bearer" in auth_header:
                            discovered_auth.append(AuthType.BEARER)
                        if "basic" in auth_header:
                            discovered_auth.append(AuthType.BASIC)

                    # Check for OAuth indicators
                    content = response.text.lower()
                    if any(term in content for term in ["oauth", "client_id", "redirect_uri"]):
                        discovered_auth.append(AuthType.OAUTH2)

                    # Check for JWT indicators
                    if any(term in content for term in ["jwt", "jsonwebtoken", "bearer"]):
                        discovered_auth.append(AuthType.JWT)

                    # Check for API key indicators
                    if any(term in content for term in ["api_key", "apikey", "x-api-key"]):
                        discovered_auth.append(AuthType.API_KEY)

                    # Check for session indicators
                    if "set-cookie" in response.headers or "session" in content:
                        discovered_auth.append(AuthType.SESSION)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(self.config.rate_limit_delay)

            # Remove duplicates
            discovered_auth = list(set(discovered_auth))

            self.logger.info(f"Discovered authentication mechanisms: {discovered_auth}")
            return discovered_auth

        except Exception as e:
            self.logger.error(f"Error discovering authentication mechanisms: {e}")
            return []

    async def test_authentication_security(self, auth_type: AuthType,
                                           credentials: AuthCredentials) -> List[Vulnerability]:
        """Test authentication security for a specific auth type"""
        vulnerabilities = []

        try:
            if auth_type == AuthType.JWT and self._jwt_analyzer:
                jwt_vulns = await self._jwt_analyzer.analyze_jwt_security(credentials.value)
                vulnerabilities.extend(jwt_vulns)

            elif auth_type == AuthType.OAUTH2 and self._oauth_tester:
                oauth_vulns = await self._oauth_tester.test_oauth_flows(credentials)
                vulnerabilities.extend(oauth_vulns)

            elif auth_type == AuthType.API_KEY and self._api_key_manager:
                api_key_vulns = await self._api_key_manager.test_api_key_security(credentials)
                vulnerabilities.extend(api_key_vulns)

            elif auth_type == AuthType.SESSION and self._session_analyzer:
                session_vulns = await self._session_analyzer.analyze_session_security(credentials)
                vulnerabilities.extend(session_vulns)

            # Test general authentication bypass techniques
            if self._auth_bypass_tester:
                bypass_vulns = await self._auth_bypass_tester.test_auth_bypass(
                    self.config.target_url, auth_type, credentials
                )
                vulnerabilities.extend(bypass_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing authentication security: {e}")
            return []

    async def brute_force_tokens(self, auth_type: AuthType,
                                 sample_token: str) -> List[Vulnerability]:
        """Attempt to brute force authentication tokens"""
        if not self._token_bruteforcer:
            return []

        try:
            return await self._token_bruteforcer.brute_force_secrets(
                auth_type, sample_token, self.config.jwt_secret_wordlist
            )
        except Exception as e:
            self.logger.error(f"Error during token brute forcing: {e}")
            return []

    async def test_privilege_escalation(self, credentials: AuthCredentials,
                                        target_endpoints: List[str]) -> List[Vulnerability]:
        """Test for privilege escalation vulnerabilities"""
        vulnerabilities = []

        try:
            # Test horizontal privilege escalation (BOLA)
            for endpoint in target_endpoints:
                # Test parameter manipulation for different user IDs
                for user_id in ["1", "2", "admin", "0", "-1", "999999"]:
                    modified_endpoint = endpoint.replace("{id}", user_id)
                    modified_endpoint = modified_endpoint.replace("{user_id}", user_id)

                    response = await self._make_authenticated_request(
                        "GET", modified_endpoint, credentials
                    )

                    if response and response.status_code == 200:
                        # Analyze response for sensitive data exposure
                        if await self._contains_sensitive_data(response.text):
                            vuln = Vulnerability(
                                vuln_type="BOLA/IDOR",
                                severity="High",
                                title="Broken Object Level Authorization",
                                description=f"Endpoint {modified_endpoint} exposed unauthorized data",
                                evidence={"response": response.text[:500]},
                                endpoint=modified_endpoint
                            )
                            vulnerabilities.append(vuln)

                # Test vertical privilege escalation
                admin_headers = {
                    "X-Admin": "true",
                    "X-Role": "admin",
                    "X-Privilege": "admin",
                    "Admin": "1"
                }

                for header, value in admin_headers.items():
                    response = await self._make_authenticated_request(
                        "GET", endpoint, credentials, additional_headers={header: value}
                    )

                    if response and response.status_code == 200:
                        if await self._indicates_elevated_access(response.text):
                            vuln = Vulnerability(
                                vuln_type="BFLA",
                                severity="Critical",
                                title="Broken Function Level Authorization",
                                description=f"Header {header} granted elevated privileges",
                                evidence={"header": f"{header}: {value}"},
                                endpoint=endpoint
                            )
                            vulnerabilities.append(vuln)

                await asyncio.sleep(self.config.rate_limit_delay)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing privilege escalation: {e}")
            return []

    async def _make_authenticated_request(self, method: str, url: str,
                                          credentials: AuthCredentials,
                                          additional_headers: Optional[Dict[str, str]] = None) -> Optional[
        httpx.Response]:
        """Make an authenticated HTTP request"""
        try:
            headers = additional_headers or {}

            if credentials.method == AuthMethod.HEADER:
                if credentials.auth_type == AuthType.BEARER:
                    headers["Authorization"] = f"Bearer {credentials.value}"
                elif credentials.auth_type == AuthType.API_KEY:
                    headers["X-API-Key"] = credentials.value
                elif credentials.auth_type == AuthType.JWT:
                    headers["Authorization"] = f"Bearer {credentials.value}"

            return await self.http_client.request(method, url, headers=headers)

        except Exception as e:
            self.logger.error(f"Error making authenticated request: {e}")
            return None

    async def _contains_sensitive_data(self, content: str) -> bool:
        """Check if response contains sensitive data patterns"""
        sensitive_patterns = [
            "password", "secret", "token", "key", "private",
            "ssn", "credit_card", "email", "phone", "address"
        ]

        content_lower = content.lower()
        return any(pattern in content_lower for pattern in sensitive_patterns)

    async def _indicates_elevated_access(self, content: str) -> bool:
        """Check if response indicates elevated access"""
        admin_indicators = [
            "admin", "administrator", "root", "superuser",
            "delete", "modify", "create_user", "manage"
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in admin_indicators)

    async def run_comprehensive_auth_test(self) -> ScanResult:
        """Run comprehensive authentication security testing"""
        vulnerabilities = []

        try:
            # Initialize components
            await self.initialize()

            # Discover authentication mechanisms
            discovered_auth = await self.discover_auth_mechanisms(self.config.target_url)

            # Test each configured credential set
            for credentials in self.config.credentials:
                # Test authentication security
                auth_vulns = await self.test_authentication_security(
                    credentials.auth_type, credentials
                )
                vulnerabilities.extend(auth_vulns)

                # Test privilege escalation
                escalation_vulns = await self.test_privilege_escalation(
                    credentials, self.discovered_endpoints
                )
                vulnerabilities.extend(escalation_vulns)

                # Brute force tokens if enabled
                if self.config.test_weak_secrets:
                    brute_vulns = await self.brute_force_tokens(
                        credentials.auth_type, credentials.value
                    )
                    vulnerabilities.extend(brute_vulns)

            return ScanResult(
                scan_type="authentication",
                target_url=self.config.target_url,
                vulnerabilities=vulnerabilities,
                total_requests=len(vulnerabilities) * 10,  # Estimate
                duration=0.0  # Will be calculated by caller
            )

        except Exception as e:
            self.logger.error(f"Error during comprehensive auth test: {e}")
            return ScanResult(
                scan_type="authentication",
                target_url=self.config.target_url,
                vulnerabilities=[],
                total_requests=0,
                duration=0.0,
                error=str(e)
            )
