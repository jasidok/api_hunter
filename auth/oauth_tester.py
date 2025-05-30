"""
OAuth/OIDC Security Tester

Comprehensive OAuth 2.0 and OpenID Connect security testing including flow manipulation,
token attacks, and authorization bypass vulnerabilities.
"""

from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass
import logging
import asyncio
import urllib.parse
from urllib.parse import urlparse, parse_qs
import re

import httpx

from ..core.http_client import HTTPClient
from ..core.models import Vulnerability


class OAuthFlow(Enum):
    """OAuth 2.0 flow types"""
    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    PASSWORD = "password"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    REFRESH_TOKEN = "refresh_token"


class OAuthVulnerabilityType(Enum):
    """OAuth vulnerability types"""
    OPEN_REDIRECT = "open_redirect"
    CSRF_STATE_BYPASS = "csrf_state_bypass"
    CODE_INJECTION = "code_injection"
    WEAK_CLIENT_SECRET = "weak_client_secret"
    SCOPE_MANIPULATION = "scope_manipulation"
    REDIRECT_URI_BYPASS = "redirect_uri_bypass"
    TOKEN_FIXATION = "token_fixation"
    PKCE_BYPASS = "pkce_bypass"
    IMPLICIT_FLOW_ABUSE = "implicit_flow_abuse"


@dataclass
class OAuthConfig:
    """OAuth configuration for testing"""
    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    client_secret: Optional[str] = None
    redirect_uri: str = "http://localhost:8080/callback"
    scope: str = "openid profile"
    response_type: str = "code"
    grant_type: str = "authorization_code"


class OAuthTester:
    """OAuth 2.0 and OIDC security testing"""

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.logger = logging.getLogger(__name__)

    async def test_oauth_flows(self, oauth_config: OAuthConfig) -> List[Vulnerability]:
        """Test OAuth flows for security vulnerabilities"""
        vulnerabilities = []

        try:
            # Test authorization endpoint vulnerabilities
            auth_vulns = await self._test_authorization_endpoint(oauth_config)
            vulnerabilities.extend(auth_vulns)

            # Test token endpoint vulnerabilities
            token_vulns = await self._test_token_endpoint(oauth_config)
            vulnerabilities.extend(token_vulns)

            # Test redirect URI manipulation
            redirect_vulns = await self._test_redirect_uri_manipulation(oauth_config)
            vulnerabilities.extend(redirect_vulns)

            # Test state parameter bypass
            state_vulns = await self._test_state_parameter_bypass(oauth_config)
            vulnerabilities.extend(state_vulns)

            # Test scope manipulation
            scope_vulns = await self._test_scope_manipulation(oauth_config)
            vulnerabilities.extend(scope_vulns)

            # Test PKCE bypass (if applicable)
            pkce_vulns = await self._test_pkce_bypass(oauth_config)
            vulnerabilities.extend(pkce_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing OAuth flows: {e}")
            return []

    async def _test_authorization_endpoint(self, config: OAuthConfig) -> List[Vulnerability]:
        """Test authorization endpoint for vulnerabilities"""
        vulnerabilities = []

        try:
            # Test open redirect vulnerabilities
            malicious_redirects = [
                "http://evil.com",
                "https://attacker.com/steal",
                "javascript:alert('xss')",
                "data:text/html,<script>alert('xss')</script>",
                "//evil.com",
                "http://legitimate.com.evil.com",
                "http://legitimate.com@evil.com"
            ]

            for malicious_redirect in malicious_redirects:
                auth_url = self._build_auth_url(config, redirect_uri=malicious_redirect)

                try:
                    response = await self.http_client.get(auth_url, follow_redirects=False)

                    if response.status_code in [302, 301, 307, 308]:
                        location = response.headers.get('location', '')
                        if malicious_redirect in location:
                            vuln = Vulnerability(
                                vuln_type="OAUTH_OPEN_REDIRECT",
                                severity="High",
                                title="OAuth Open Redirect Vulnerability",
                                description=f"Authorization endpoint allows redirect to: {malicious_redirect}",
                                evidence={
                                    "malicious_redirect": malicious_redirect,
                                    "auth_url": auth_url,
                                    "redirect_location": location
                                },
                                endpoint=config.authorization_endpoint
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            # Test response type manipulation
            response_types = ["token", "code token", "id_token", "code id_token"]
            for response_type in response_types:
                auth_url = self._build_auth_url(config, response_type=response_type)

                try:
                    response = await self.http_client.get(auth_url, follow_redirects=False)

                    if response.status_code == 200:
                        # Check if implicit flow is unexpectedly allowed
                        if "token" in response_type and "access_token" in response.text:
                            vuln = Vulnerability(
                                vuln_type="OAUTH_IMPLICIT_FLOW_ENABLED",
                                severity="Medium",
                                title="OAuth Implicit Flow Unexpectedly Enabled",
                                description=f"Response type '{response_type}' is allowed",
                                evidence={
                                    "response_type": response_type,
                                    "auth_url": auth_url
                                },
                                endpoint=config.authorization_endpoint
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing authorization endpoint: {e}")
            return []

    async def _test_token_endpoint(self, config: OAuthConfig) -> List[Vulnerability]:
        """Test token endpoint for vulnerabilities"""
        vulnerabilities = []

        try:
            # Test client credential attacks
            if config.client_secret:
                # Test weak client secrets
                weak_secrets = [
                    "secret", "password", "123456", "client_secret",
                    config.client_id, f"{config.client_id}_secret"
                ]

                for weak_secret in weak_secrets:
                    token_data = {
                        "grant_type": "client_credentials",
                        "client_id": config.client_id,
                        "client_secret": weak_secret,
                        "scope": config.scope
                    }

                    try:
                        response = await self.http_client.post(
                            config.token_endpoint,
                            data=token_data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"}
                        )

                        if response.status_code == 200 and "access_token" in response.text:
                            vuln = Vulnerability(
                                vuln_type="OAUTH_WEAK_CLIENT_SECRET",
                                severity="Critical",
                                title="OAuth Weak Client Secret",
                                description=f"Client authenticated with weak secret: {weak_secret}",
                                evidence={
                                    "weak_secret": weak_secret,
                                    "client_id": config.client_id,
                                    "response": response.text[:500]
                                },
                                endpoint=config.token_endpoint
                            )
                            vulnerabilities.append(vuln)
                            break

                    except httpx.RequestError:
                        continue

                    await asyncio.sleep(0.5)

            # Test grant type manipulation
            malicious_grant_types = [
                "password",  # Resource Owner Password Credentials
                "implicit",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code"
            ]

            for grant_type in malicious_grant_types:
                token_data = {
                    "grant_type": grant_type,
                    "client_id": config.client_id,
                    "scope": config.scope
                }

                if config.client_secret:
                    token_data["client_secret"] = config.client_secret

                try:
                    response = await self.http_client.post(
                        config.token_endpoint,
                        data=token_data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"}
                    )

                    if response.status_code == 200 and "access_token" in response.text:
                        vuln = Vulnerability(
                            vuln_type="OAUTH_GRANT_TYPE_MANIPULATION",
                            severity="Medium",
                            title="OAuth Grant Type Manipulation",
                            description=f"Unexpected grant type '{grant_type}' accepted",
                            evidence={
                                "grant_type": grant_type,
                                "response": response.text[:500]
                            },
                            endpoint=config.token_endpoint
                        )
                        vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing token endpoint: {e}")
            return []

    async def _test_redirect_uri_manipulation(self, config: OAuthConfig) -> List[Vulnerability]:
        """Test redirect URI manipulation attacks"""
        vulnerabilities = []

        try:
            # Test redirect URI bypass techniques
            original_redirect = config.redirect_uri
            bypass_attempts = [
                f"{original_redirect}.evil.com",
                f"{original_redirect}/../../evil.com",
                f"{original_redirect}#evil.com",
                f"{original_redirect}?evil.com",
                f"{original_redirect}@evil.com",
                original_redirect.replace("://", "://evil.com@"),
                original_redirect + "%2Eevil.com",
                original_redirect + "%0D%0ALocation:%20http://evil.com"
            ]

            for bypass_uri in bypass_attempts:
                auth_url = self._build_auth_url(config, redirect_uri=bypass_uri)

                try:
                    response = await self.http_client.get(auth_url, follow_redirects=False)

                    # Check if the bypass was accepted
                    if response.status_code in [200, 302, 301]:
                        location = response.headers.get('location', '')
                        if 'evil.com' in location or 'evil.com' in response.text:
                            vuln = Vulnerability(
                                vuln_type="OAUTH_REDIRECT_URI_BYPASS",
                                severity="High",
                                title="OAuth Redirect URI Bypass",
                                description=f"Redirect URI validation bypassed: {bypass_uri}",
                                evidence={
                                    "original_redirect": original_redirect,
                                    "bypass_redirect": bypass_uri,
                                    "response_location": location
                                },
                                endpoint=config.authorization_endpoint
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing redirect URI manipulation: {e}")
            return []

    async def _test_state_parameter_bypass(self, config: OAuthConfig) -> List[Vulnerability]:
        """Test state parameter CSRF protection bypass"""
        vulnerabilities = []

        try:
            # Test missing state parameter
            auth_url_no_state = self._build_auth_url(config, include_state=False)

            try:
                response = await self.http_client.get(auth_url_no_state, follow_redirects=False)

                if response.status_code in [200, 302]:
                    vuln = Vulnerability(
                        vuln_type="OAUTH_MISSING_STATE",
                        severity="Medium",
                        title="OAuth Missing State Parameter",
                        description="Authorization request accepted without state parameter",
                        evidence={
                            "auth_url": auth_url_no_state,
                            "status_code": response.status_code
                        },
                        endpoint=config.authorization_endpoint
                    )
                    vulnerabilities.append(vuln)

            except httpx.RequestError:
                pass

            # Test state parameter manipulation
            malicious_states = [
                "",  # Empty state
                "' OR '1'='1",  # SQL injection attempt
                "<script>alert('xss')</script>",  # XSS attempt
                "../../../evil",  # Path traversal
                "javascript:alert('xss')"  # JavaScript URL
            ]

            for malicious_state in malicious_states:
                auth_url = self._build_auth_url(config, state=malicious_state)

                try:
                    response = await self.http_client.get(auth_url, follow_redirects=False)

                    if response.status_code == 200:
                        # Check if malicious state is reflected
                        if malicious_state in response.text:
                            vuln = Vulnerability(
                                vuln_type="OAUTH_STATE_INJECTION",
                                severity="Medium",
                                title="OAuth State Parameter Injection",
                                description=f"Malicious state parameter reflected: {malicious_state}",
                                evidence={
                                    "malicious_state": malicious_state,
                                    "auth_url": auth_url
                                },
                                endpoint=config.authorization_endpoint
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing state parameter bypass: {e}")
            return []

    async def _test_scope_manipulation(self, config: OAuthConfig) -> List[Vulnerability]:
        """Test scope manipulation attacks"""
        vulnerabilities = []

        try:
            # Test privilege escalation through scope manipulation
            escalated_scopes = [
                "admin",
                "root",
                "write",
                "delete",
                "manage",
                "superuser",
                "*",
                "openid profile email admin",
                config.scope + " admin"
            ]

            for scope in escalated_scopes:
                auth_url = self._build_auth_url(config, scope=scope)

                try:
                    response = await self.http_client.get(auth_url, follow_redirects=False)

                    if response.status_code in [200, 302]:
                        # Check if elevated scope was accepted
                        if "scope" in response.text and ("admin" in response.text or "*" in response.text):
                            vuln = Vulnerability(
                                vuln_type="OAUTH_SCOPE_ESCALATION",
                                severity="High",
                                title="OAuth Scope Privilege Escalation",
                                description=f"Elevated scope accepted: {scope}",
                                evidence={
                                    "original_scope": config.scope,
                                    "escalated_scope": scope,
                                    "auth_url": auth_url
                                },
                                endpoint=config.authorization_endpoint
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing scope manipulation: {e}")
            return []

    async def _test_pkce_bypass(self, config: OAuthConfig) -> List[Vulnerability]:
        """Test PKCE (Proof Key for Code Exchange) bypass"""
        vulnerabilities = []

        try:
            # Test authorization without PKCE parameters
            auth_url_no_pkce = self._build_auth_url(config)

            try:
                response = await self.http_client.get(auth_url_no_pkce, follow_redirects=False)

                if response.status_code in [200, 302]:
                    # Check if PKCE is not enforced
                    location = response.headers.get('location', '')
                    if 'code=' in location or 'code=' in response.text:
                        vuln = Vulnerability(
                            vuln_type="OAUTH_PKCE_NOT_ENFORCED",
                            severity="Medium",
                            title="OAuth PKCE Not Enforced",
                            description="Authorization code granted without PKCE challenge",
                            evidence={
                                "auth_url": auth_url_no_pkce,
                                "response_location": location
                            },
                            endpoint=config.authorization_endpoint
                        )
                        vulnerabilities.append(vuln)

            except httpx.RequestError:
                pass

            # Test weak PKCE challenge
            weak_challenges = [
                "123456",
                "password",
                "challenge",
                "a" * 43,  # Minimum length
                "test"
            ]

            for challenge in weak_challenges:
                auth_url = self._build_auth_url(
                    config,
                    code_challenge=challenge,
                    code_challenge_method="plain"
                )

                try:
                    response = await self.http_client.get(auth_url, follow_redirects=False)

                    if response.status_code in [200, 302]:
                        location = response.headers.get('location', '')
                        if 'code=' in location:
                            vuln = Vulnerability(
                                vuln_type="OAUTH_WEAK_PKCE_CHALLENGE",
                                severity="Medium",
                                title="OAuth Weak PKCE Challenge",
                                description=f"Weak PKCE challenge accepted: {challenge}",
                                evidence={
                                    "weak_challenge": challenge,
                                    "challenge_method": "plain",
                                    "auth_url": auth_url
                                },
                                endpoint=config.authorization_endpoint
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing PKCE bypass: {e}")
            return []

    def _build_auth_url(self, config: OAuthConfig, **overrides) -> str:
        """Build authorization URL with parameters"""
        params = {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": config.response_type,
            "scope": config.scope,
            "state": "test_state_123"
        }

        # Apply overrides
        for key, value in overrides.items():
            if key == "include_state" and not value:
                params.pop("state", None)
            elif key == "code_challenge":
                params["code_challenge"] = value
            elif key == "code_challenge_method":
                params["code_challenge_method"] = value
            else:
                params[key] = value

        # Build URL
        query_string = urllib.parse.urlencode(params)
        return f"{config.authorization_endpoint}?{query_string}"

    async def discover_oauth_endpoints(self, base_url: str) -> Dict[str, str]:
        """Discover OAuth endpoints from well-known URLs"""
        endpoints = {}

        try:
            # Try well-known OIDC discovery
            discovery_urls = [
                f"{base_url}/.well-known/openid_configuration",
                f"{base_url}/.well-known/oauth-authorization-server",
                f"{base_url}/oauth/.well-known/openid_configuration",
                f"{base_url}/auth/.well-known/openid_configuration"
            ]

            for discovery_url in discovery_urls:
                try:
                    response = await self.http_client.get(discovery_url)

                    if response.status_code == 200:
                        config = response.json()

                        endpoints.update({
                            "authorization_endpoint": config.get("authorization_endpoint"),
                            "token_endpoint": config.get("token_endpoint"),
                            "userinfo_endpoint": config.get("userinfo_endpoint"),
                            "jwks_uri": config.get("jwks_uri"),
                            "issuer": config.get("issuer")
                        })

                        # Remove None values
                        endpoints = {k: v for k, v in endpoints.items() if v is not None}
                        break

                except (httpx.RequestError, ValueError):
                    continue

                await asyncio.sleep(0.5)

            # If discovery failed, try common paths
            if not endpoints:
                common_paths = {
                    "authorization_endpoint": ["/oauth/authorize", "/auth/oauth/authorize", "/oauth2/authorize"],
                    "token_endpoint": ["/oauth/token", "/auth/oauth/token", "/oauth2/token"],
                    "userinfo_endpoint": ["/oauth/userinfo", "/auth/userinfo", "/oauth2/userinfo"]
                }

                for endpoint_type, paths in common_paths.items():
                    for path in paths:
                        test_url = f"{base_url}{path}"

                        try:
                            response = await self.http_client.get(test_url)

                            if response.status_code in [200, 400, 405]:  # Endpoint exists
                                endpoints[endpoint_type] = test_url
                                break

                        except httpx.RequestError:
                            continue

                        await asyncio.sleep(0.5)

            return endpoints

        except Exception as e:
            self.logger.error(f"Error discovering OAuth endpoints: {e}")
            return {}
