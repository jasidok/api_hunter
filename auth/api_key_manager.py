"""
API Key Security Manager

Comprehensive API key security testing including key enumeration, 
privilege testing, and security configuration analysis.
"""

from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass
import logging
import asyncio
import re
import secrets
import string

import httpx

from ..core.http_client import HTTPClient
from ..core.models import Vulnerability
from .auth_manager import AuthCredentials, AuthMethod, AuthType


class APIKeyLocation(Enum):
    """API key location in requests"""
    HEADER = "header"
    QUERY_PARAM = "query"
    BODY = "body"
    COOKIE = "cookie"


class APIKeyManager:
    """API key security testing and management"""

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.logger = logging.getLogger(__name__)

        # Common API key header names
        self.common_headers = [
            "X-API-Key", "X-Api-Key", "X-API-TOKEN", "X-Auth-Token",
            "Authorization", "Auth", "Token", "Access-Token",
            "X-Access-Token", "X-Auth", "API-Key", "ApiKey",
            "X-Client-Token", "Client-Token", "App-Token", "X-App-Token"
        ]

        # Common query parameter names
        self.common_params = [
            "api_key", "apikey", "key", "token", "access_token",
            "auth_token", "auth", "client_key", "app_key"
        ]

    async def test_api_key_security(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Comprehensive API key security testing"""
        vulnerabilities = []

        try:
            # Test API key format and strength
            format_vulns = await self._test_api_key_format(credentials.value)
            vulnerabilities.extend(format_vulns)

            # Test API key enumeration
            enum_vulns = await self._test_api_key_enumeration(credentials)
            vulnerabilities.extend(enum_vulns)

            # Test API key brute force
            brute_vulns = await self._test_api_key_brute_force(credentials)
            vulnerabilities.extend(brute_vulns)

            # Test rate limiting on API key usage
            rate_vulns = await self._test_api_key_rate_limiting(credentials)
            vulnerabilities.extend(rate_vulns)

            # Test API key privilege escalation
            priv_vulns = await self._test_api_key_privileges(credentials)
            vulnerabilities.extend(priv_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing API key security: {e}")
            return []

    async def _test_api_key_format(self, api_key: str) -> List[Vulnerability]:
        """Test API key format and strength"""
        vulnerabilities = []

        try:
            # Check key length
            if len(api_key) < 16:
                vuln = Vulnerability(
                    vuln_type="API_KEY_WEAK_FORMAT",
                    severity="Medium",
                    title="API Key Too Short",
                    description=f"API key length ({len(api_key)}) is below recommended minimum (16)",
                    evidence={"key_length": len(api_key), "api_key": api_key[:8] + "..."},
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            # Check for predictable patterns
            predictable_patterns = [
                r"^(test|demo|example|sample)",
                r"^(admin|root|user|guest)",
                r"^\d+$",  # Only numbers
                r"^[a-z]+$",  # Only lowercase letters
                r"^(abc|123|qwe|asd)",
                r"(password|secret|key|token)$"
            ]

            for pattern in predictable_patterns:
                if re.search(pattern, api_key.lower()):
                    vuln = Vulnerability(
                        vuln_type="API_KEY_PREDICTABLE_PATTERN",
                        severity="High",
                        title="API Key Contains Predictable Pattern",
                        description=f"API key matches predictable pattern: {pattern}",
                        evidence={"pattern": pattern, "api_key": api_key[:8] + "..."},
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

            # Check entropy
            entropy = self._calculate_entropy(api_key)
            if entropy < 3.0:  # Low entropy threshold
                vuln = Vulnerability(
                    vuln_type="API_KEY_LOW_ENTROPY",
                    severity="High",
                    title="API Key Low Entropy",
                    description=f"API key has low entropy ({entropy:.2f}), indicating weak randomness",
                    evidence={"entropy": entropy, "api_key": api_key[:8] + "..."},
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            # Check for common weak keys
            weak_keys = [
                "test", "demo", "example", "sample", "12345", "admin",
                "password", "secret", "key", "token", "api_key",
                "changeme", "default", "guest", "user"
            ]

            if api_key.lower() in weak_keys:
                vuln = Vulnerability(
                    vuln_type="API_KEY_COMMON_WEAK",
                    severity="Critical",
                    title="Common Weak API Key",
                    description=f"API key is a common weak value: {api_key}",
                    evidence={"weak_key": api_key},
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing API key format: {e}")
            return []

    async def _test_api_key_enumeration(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Test for API key enumeration vulnerabilities"""
        vulnerabilities = []

        try:
            # Test different key variations
            base_key = credentials.value

            # Try sequential keys if key appears to be numeric
            if base_key.isdigit():
                test_keys = [
                    str(int(base_key) + 1),
                    str(int(base_key) - 1),
                    str(int(base_key) + 10),
                    str(int(base_key) - 10)
                ]

                for test_key in test_keys:
                    if await self._test_api_key_validity(test_key, credentials.method):
                        vuln = Vulnerability(
                            vuln_type="API_KEY_ENUMERABLE",
                            severity="High",
                            title="API Key Sequential Enumeration",
                            description=f"Sequential API key {test_key} is valid",
                            evidence={
                                "original_key": base_key,
                                "enumerated_key": test_key,
                                "method": credentials.method.value
                            },
                            endpoint="N/A"
                        )
                        vulnerabilities.append(vuln)

            # Test with common suffixes/prefixes
            if len(base_key) > 8:
                test_variations = [
                    base_key[:-1] + "1",  # Last char + 1
                    base_key[:-1] + "0",  # Last char to 0
                    "test_" + base_key,  # Test prefix
                    base_key + "_test",  # Test suffix
                    base_key.replace(base_key[-1], str(int(base_key[-1]) + 1) if base_key[-1].isdigit() else 'a')
                ]

                for variation in test_variations:
                    if await self._test_api_key_validity(variation, credentials.method):
                        vuln = Vulnerability(
                            vuln_type="API_KEY_VARIATION_VALID",
                            severity="Medium",
                            title="API Key Variation Valid",
                            description=f"API key variation {variation[:8]}... is valid",
                            evidence={
                                "original_key": base_key[:8] + "...",
                                "variation_key": variation[:8] + "...",
                                "method": credentials.method.value
                            },
                            endpoint="N/A"
                        )
                        vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing API key enumeration: {e}")
            return []

    async def _test_api_key_brute_force(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Test API key brute force protection"""
        vulnerabilities = []

        try:
            # Generate invalid API keys for brute force testing
            invalid_keys = []

            # Generate random keys of same length
            key_length = len(credentials.value)
            for _ in range(20):  # Test with 20 invalid keys
                invalid_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(key_length))
                invalid_keys.append(invalid_key)

            # Test rate limiting
            successful_attempts = 0
            total_attempts = 0

            for invalid_key in invalid_keys:
                try:
                    is_valid = await self._test_api_key_validity(invalid_key, credentials.method)
                    total_attempts += 1

                    if is_valid:
                        successful_attempts += 1

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:  # Rate limited
                        # This is good - rate limiting is working
                        break
                    elif e.response.status_code in [401, 403]:
                        # Expected for invalid keys
                        total_attempts += 1

                except httpx.RequestError:
                    continue

                # Small delay to avoid overwhelming the system
                await asyncio.sleep(0.1)

            # Check if too many attempts were allowed
            if total_attempts >= 15:  # No rate limiting detected
                vuln = Vulnerability(
                    vuln_type="API_KEY_NO_RATE_LIMITING",
                    severity="Medium",
                    title="API Key Brute Force Not Rate Limited",
                    description=f"Attempted {total_attempts} API key validations without rate limiting",
                    evidence={
                        "total_attempts": total_attempts,
                        "successful_attempts": successful_attempts
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing API key brute force: {e}")
            return []

    async def _test_api_key_rate_limiting(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Test rate limiting on API key usage"""
        vulnerabilities = []

        try:
            # Make multiple rapid requests with the same API key
            request_count = 0
            success_count = 0
            rate_limited = False

            for i in range(50):  # Try 50 rapid requests
                try:
                    response = await self._make_api_key_request("/", credentials.value, credentials.method)
                    request_count += 1

                    if response and response.status_code == 200:
                        success_count += 1
                    elif response and response.status_code == 429:
                        rate_limited = True
                        break

                except httpx.RequestError:
                    continue

                # Very small delay
                await asyncio.sleep(0.05)

            # Check if rate limiting is missing
            if not rate_limited and success_count > 30:
                vuln = Vulnerability(
                    vuln_type="API_KEY_NO_USAGE_RATE_LIMIT",
                    severity="Medium",
                    title="API Key Usage Not Rate Limited",
                    description=f"Made {success_count} successful requests without rate limiting",
                    evidence={
                        "successful_requests": success_count,
                        "total_requests": request_count
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing API key rate limiting: {e}")
            return []

    async def _test_api_key_privileges(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Test API key privilege escalation"""
        vulnerabilities = []

        try:
            # Test access to admin endpoints
            admin_endpoints = [
                "/admin", "/admin/", "/admin/users", "/admin/config",
                "/api/admin", "/api/admin/", "/api/v1/admin",
                "/management", "/manage", "/control", "/settings"
            ]

            for endpoint in admin_endpoints:
                try:
                    response = await self._make_api_key_request(endpoint, credentials.value, credentials.method)

                    if response and response.status_code == 200:
                        # Check if response indicates admin access
                        admin_indicators = [
                            "admin", "administrator", "management", "control",
                            "users", "delete", "create", "modify", "manage"
                        ]

                        response_text = response.text.lower()
                        if any(indicator in response_text for indicator in admin_indicators):
                            vuln = Vulnerability(
                                vuln_type="API_KEY_ADMIN_ACCESS",
                                severity="Critical",
                                title="API Key Grants Admin Access",
                                description=f"API key provides access to admin endpoint: {endpoint}",
                                evidence={
                                    "endpoint": endpoint,
                                    "response_snippet": response.text[:500]
                                },
                                endpoint=endpoint
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            # Test privilege escalation through headers
            privilege_headers = {
                "X-Admin": "true",
                "X-Role": "admin",
                "X-Privilege": "admin",
                "Admin": "1",
                "Role": "administrator",
                "X-User-Role": "admin"
            }

            test_endpoint = "/api/users"  # Common endpoint

            for header, value in privilege_headers.items():
                try:
                    headers = self._build_api_key_headers(credentials.value, credentials.method)
                    headers[header] = value

                    response = await self.http_client.get(test_endpoint, headers=headers)

                    if response and response.status_code == 200:
                        # Check if elevated access was granted
                        if await self._indicates_elevated_access(response.text):
                            vuln = Vulnerability(
                                vuln_type="API_KEY_PRIVILEGE_ESCALATION",
                                severity="High",
                                title="API Key Privilege Escalation",
                                description=f"Header {header} granted elevated privileges",
                                evidence={
                                    "escalation_header": f"{header}: {value}",
                                    "endpoint": test_endpoint,
                                    "response_snippet": response.text[:500]
                                },
                                endpoint=test_endpoint
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.5)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing API key privileges: {e}")
            return []

    async def _test_api_key_validity(self, api_key: str, method: AuthMethod) -> bool:
        """Test if an API key is valid"""
        try:
            response = await self._make_api_key_request("/", api_key, method)
            return response is not None and response.status_code in [200, 201, 204]
        except:
            return False

    async def _make_api_key_request(self, endpoint: str, api_key: str, method: AuthMethod) -> Optional[httpx.Response]:
        """Make a request with API key authentication"""
        try:
            headers = self._build_api_key_headers(api_key, method)

            if method == AuthMethod.QUERY:
                # Add API key as query parameter
                params = {"api_key": api_key}
                return await self.http_client.get(endpoint, headers={}, params=params)
            else:
                return await self.http_client.get(endpoint, headers=headers)

        except Exception as e:
            self.logger.error(f"Error making API key request: {e}")
            return None

    def _build_api_key_headers(self, api_key: str, method: AuthMethod) -> Dict[str, str]:
        """Build headers for API key authentication"""
        headers = {}

        if method == AuthMethod.HEADER:
            # Try common header names
            headers["X-API-Key"] = api_key
        elif method == AuthMethod.BODY:
            headers["Content-Type"] = "application/json"

        return headers

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        try:
            import math
            from collections import Counter

            # Count character frequencies
            counter = Counter(text)
            length = len(text)

            # Calculate entropy
            entropy = 0.0
            for count in counter.values():
                probability = count / length
                entropy -= probability * math.log2(probability)

            return entropy

        except:
            return 0.0

    async def _indicates_elevated_access(self, content: str) -> bool:
        """Check if response indicates elevated access"""
        admin_indicators = [
            "admin", "administrator", "root", "superuser", "management",
            "delete", "modify", "create_user", "manage", "control",
            "all users", "user list", "system config"
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in admin_indicators)

    async def discover_api_key_locations(self, target_url: str) -> List[APIKeyLocation]:
        """Discover where API keys are expected in requests"""
        discovered_locations = []

        try:
            # Test common API key locations
            test_key = "test_api_key_123"

            # Test header location
            try:
                response = await self.http_client.get(
                    target_url,
                    headers={"X-API-Key": test_key}
                )

                if response.status_code in [401, 403, 400]:
                    # API key was processed (even if invalid)
                    discovered_locations.append(APIKeyLocation.HEADER)
            except:
                pass

            # Test query parameter location
            try:
                response = await self.http_client.get(
                    target_url,
                    params={"api_key": test_key}
                )

                if response.status_code in [401, 403, 400]:
                    discovered_locations.append(APIKeyLocation.QUERY_PARAM)
            except:
                pass

            # Test body location for POST endpoints
            try:
                response = await self.http_client.post(
                    target_url,
                    json={"api_key": test_key}
                )

                if response.status_code in [401, 403, 400]:
                    discovered_locations.append(APIKeyLocation.BODY)
            except:
                pass

            return discovered_locations

        except Exception as e:
            self.logger.error(f"Error discovering API key locations: {e}")
            return []
