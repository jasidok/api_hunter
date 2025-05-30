"""
Authentication Bypass Tester

Comprehensive authentication bypass testing including header manipulation,
path traversal, method bypass, and various evasion techniques.
"""

from typing import Dict, List, Optional, Any
from enum import Enum
import logging
import asyncio
from urllib.parse import quote, unquote

import httpx

from ..core.http_client import HTTPClient
from ..core.models import Vulnerability
from .auth_manager import AuthCredentials, AuthType


class BypassTechnique(Enum):
    """Authentication bypass techniques"""
    HEADER_MANIPULATION = "header_manipulation"
    METHOD_BYPASS = "method_bypass"
    PATH_TRAVERSAL = "path_traversal"
    PARAMETER_POLLUTION = "parameter_pollution"
    ENCODING_BYPASS = "encoding_bypass"
    IP_WHITELIST_BYPASS = "ip_whitelist_bypass"
    REFERRER_BYPASS = "referrer_bypass"


class AuthBypassTester:
    """Authentication bypass testing"""

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.logger = logging.getLogger(__name__)

    async def test_auth_bypass(self, target_url: str, auth_type: AuthType,
                               credentials: AuthCredentials) -> List[Vulnerability]:
        """Test various authentication bypass techniques"""
        vulnerabilities = []

        try:
            # Test header manipulation bypasses
            header_vulns = await self._test_header_manipulation(target_url)
            vulnerabilities.extend(header_vulns)

            # Test HTTP method bypasses
            method_vulns = await self._test_method_bypass(target_url)
            vulnerabilities.extend(method_vulns)

            # Test path traversal bypasses
            path_vulns = await self._test_path_traversal_bypass(target_url)
            vulnerabilities.extend(path_vulns)

            # Test encoding bypasses
            encoding_vulns = await self._test_encoding_bypass(target_url)
            vulnerabilities.extend(encoding_vulns)

            # Test IP whitelist bypasses
            ip_vulns = await self._test_ip_whitelist_bypass(target_url)
            vulnerabilities.extend(ip_vulns)

            # Test referrer bypasses
            referrer_vulns = await self._test_referrer_bypass(target_url)
            vulnerabilities.extend(referrer_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing auth bypass: {e}")
            return []

    async def _test_header_manipulation(self, target_url: str) -> List[Vulnerability]:
        """Test authentication bypass through header manipulation"""
        vulnerabilities = []

        try:
            # Common bypass headers
            bypass_headers = {
                # Admin/privilege headers
                "X-Admin": "true",
                "X-Role": "admin",
                "X-Privilege": "admin",
                "Admin": "1",
                "Role": "administrator",
                "X-User-Role": "admin",
                "X-Auth-Admin": "true",

                # Internal/debug headers
                "X-Debug": "true",
                "X-Internal": "true",
                "X-Test": "true",
                "Debug": "1",
                "Internal": "true",

                # Forwarded/proxy headers
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "X-Forwarded-Host": "localhost",

                # Authentication bypass headers
                "X-Skip-Auth": "true",
                "X-Bypass-Auth": "true",
                "X-No-Auth": "true",
                "X-Auth-Skip": "1",

                # User spoofing headers
                "X-User": "admin",
                "X-Username": "administrator",
                "X-User-ID": "1",
                "X-UID": "0",

                # Custom application headers
                "X-API-KEY": "bypass",
                "X-Access-Token": "admin",
                "Authorization": "Bearer admin",
                "X-Auth-Token": "bypass"
            }

            # Test each bypass header
            for header, value in bypass_headers.items():
                try:
                    response = await self.http_client.get(
                        target_url,
                        headers={header: value}
                    )

                    if response and response.status_code == 200:
                        # Check if bypass was successful
                        if await self._indicates_successful_bypass(response.text):
                            vuln = Vulnerability(
                                vuln_type="AUTH_BYPASS_HEADER",
                                severity="High",
                                title="Authentication Bypass via Header Manipulation",
                                description=f"Authentication bypassed using header: {header}: {value}",
                                evidence={
                                    "bypass_header": f"{header}: {value}",
                                    "response_snippet": response.text[:500]
                                },
                                endpoint=target_url
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.3)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing header manipulation: {e}")
            return []

    async def _test_method_bypass(self, target_url: str) -> List[Vulnerability]:
        """Test authentication bypass through HTTP method manipulation"""
        vulnerabilities = []

        try:
            # Alternative HTTP methods
            methods = ["HEAD", "OPTIONS", "TRACE", "PATCH", "DELETE", "PUT"]

            for method in methods:
                try:
                    response = await self.http_client.request(method, target_url)

                    if response and response.status_code == 200:
                        vuln = Vulnerability(
                            vuln_type="AUTH_BYPASS_METHOD",
                            severity="Medium",
                            title="Authentication Bypass via HTTP Method",
                            description=f"Authentication bypassed using {method} method",
                            evidence={
                                "method": method,
                                "status_code": response.status_code,
                                "response_snippet": response.text[:500]
                            },
                            endpoint=target_url
                        )
                        vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.3)

            # Test method override headers
            override_headers = [
                {"X-HTTP-Method-Override": "GET"},
                {"X-Method-Override": "GET"},
                {"_method": "GET"}
            ]

            for override_header in override_headers:
                try:
                    response = await self.http_client.post(
                        target_url,
                        headers=override_header
                    )

                    if response and response.status_code == 200:
                        vuln = Vulnerability(
                            vuln_type="AUTH_BYPASS_METHOD_OVERRIDE",
                            severity="Medium",
                            title="Authentication Bypass via Method Override",
                            description=f"Authentication bypassed using method override: {override_header}",
                            evidence={
                                "override_header": str(override_header),
                                "response_snippet": response.text[:500]
                            },
                            endpoint=target_url
                        )
                        vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.3)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing method bypass: {e}")
            return []

    async def _test_path_traversal_bypass(self, target_url: str) -> List[Vulnerability]:
        """Test authentication bypass through path manipulation"""
        vulnerabilities = []

        try:
            # Path traversal patterns
            traversal_patterns = [
                "../",
                "..%2f",
                "..%252f",
                "%2e%2e%2f",
                "%2e%2e/",
                ".%2e/",
                "%2e./",
                "....//",
                "..;/",
                "..//",
                "/..",
                "\\..\\",
                "%c0%af",
                "%5c%2e%2e%5c",
                "..%5c",
                "..%255c"
            ]

            base_path = target_url.rstrip('/')

            for pattern in traversal_patterns:
                # Test various combinations
                test_urls = [
                    f"{base_path}/{pattern}",
                    f"{base_path}{pattern}",
                    f"{base_path}/{pattern}admin",
                    f"{base_path}/{pattern}config",
                    f"{base_path}/{pattern}secret"
                ]

                for test_url in test_urls:
                    try:
                        response = await self.http_client.get(test_url)

                        if response and response.status_code == 200:
                            if await self._indicates_successful_bypass(response.text):
                                vuln = Vulnerability(
                                    vuln_type="AUTH_BYPASS_PATH_TRAVERSAL",
                                    severity="High",
                                    title="Authentication Bypass via Path Traversal",
                                    description=f"Authentication bypassed using path: {test_url}",
                                    evidence={
                                        "bypass_path": test_url,
                                        "pattern": pattern,
                                        "response_snippet": response.text[:500]
                                    },
                                    endpoint=test_url
                                )
                                vulnerabilities.append(vuln)

                    except httpx.RequestError:
                        continue

                    await asyncio.sleep(0.2)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing path traversal bypass: {e}")
            return []

    async def _test_encoding_bypass(self, target_url: str) -> List[Vulnerability]:
        """Test authentication bypass through URL encoding"""
        vulnerabilities = []

        try:
            # Different encoding variations of the URL
            encoding_variations = [
                target_url.replace("/", "%2f"),
                target_url.replace("/", "%252f"),
                target_url.replace("/", "\\"),
                target_url.replace("/", "%5c"),
                target_url.replace("/", "%255c"),
                quote(target_url, safe=''),
                quote(quote(target_url, safe=''), safe=''),
                target_url.upper(),
                target_url.lower()
            ]

            for encoded_url in encoding_variations:
                try:
                    response = await self.http_client.get(encoded_url)

                    if response and response.status_code == 200:
                        if await self._indicates_successful_bypass(response.text):
                            vuln = Vulnerability(
                                vuln_type="AUTH_BYPASS_ENCODING",
                                severity="Medium",
                                title="Authentication Bypass via URL Encoding",
                                description=f"Authentication bypassed using encoded URL: {encoded_url}",
                                evidence={
                                    "original_url": target_url,
                                    "encoded_url": encoded_url,
                                    "response_snippet": response.text[:500]
                                },
                                endpoint=encoded_url
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.3)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing encoding bypass: {e}")
            return []

    async def _test_ip_whitelist_bypass(self, target_url: str) -> List[Vulnerability]:
        """Test authentication bypass through IP spoofing"""
        vulnerabilities = []

        try:
            # Common internal/trusted IP addresses
            trusted_ips = [
                "127.0.0.1",
                "localhost",
                "10.0.0.1",
                "192.168.1.1",
                "172.16.0.1",
                "0.0.0.0",
                "::1",
                "0:0:0:0:0:0:0:1"
            ]

            # Headers that might be used for IP checking
            ip_headers = [
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Originating-IP",
                "X-Remote-IP",
                "X-Client-IP",
                "X-Forwarded",
                "X-Cluster-Client-IP",
                "True-Client-IP",
                "CF-Connecting-IP",
                "X-Azure-ClientIP"
            ]

            for ip in trusted_ips:
                for header in ip_headers:
                    try:
                        response = await self.http_client.get(
                            target_url,
                            headers={header: ip}
                        )

                        if response and response.status_code == 200:
                            if await self._indicates_successful_bypass(response.text):
                                vuln = Vulnerability(
                                    vuln_type="AUTH_BYPASS_IP_SPOOFING",
                                    severity="High",
                                    title="Authentication Bypass via IP Spoofing",
                                    description=f"Authentication bypassed using {header}: {ip}",
                                    evidence={
                                        "spoofed_header": f"{header}: {ip}",
                                        "response_snippet": response.text[:500]
                                    },
                                    endpoint=target_url
                                )
                                vulnerabilities.append(vuln)

                    except httpx.RequestError:
                        continue

                    await asyncio.sleep(0.2)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing IP whitelist bypass: {e}")
            return []

    async def _test_referrer_bypass(self, target_url: str) -> List[Vulnerability]:
        """Test authentication bypass through referrer manipulation"""
        vulnerabilities = []

        try:
            # Common trusted referrers
            trusted_referrers = [
                "https://localhost",
                "https://127.0.0.1",
                "https://admin.local",
                "https://internal.local",
                "https://trusted.local",
                "https://api.local",
                "http://localhost",
                "http://127.0.0.1"
            ]

            for referrer in trusted_referrers:
                try:
                    response = await self.http_client.get(
                        target_url,
                        headers={"Referer": referrer}
                    )

                    if response and response.status_code == 200:
                        if await self._indicates_successful_bypass(response.text):
                            vuln = Vulnerability(
                                vuln_type="AUTH_BYPASS_REFERRER",
                                severity="Medium",
                                title="Authentication Bypass via Referrer",
                                description=f"Authentication bypassed using referrer: {referrer}",
                                evidence={
                                    "referrer": referrer,
                                    "response_snippet": response.text[:500]
                                },
                                endpoint=target_url
                            )
                            vulnerabilities.append(vuln)

                except httpx.RequestError:
                    continue

                await asyncio.sleep(0.3)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing referrer bypass: {e}")
            return []

    async def _indicates_successful_bypass(self, content: str) -> bool:
        """Check if response indicates successful authentication bypass"""
        try:
            # Indicators of successful access
            success_indicators = [
                "welcome", "dashboard", "admin", "profile", "settings",
                "logout", "user", "account", "authenticated", "authorized",
                "success", "logged in", "login successful", "access granted"
            ]

            # Indicators of failed access
            failure_indicators = [
                "unauthorized", "forbidden", "access denied", "login required",
                "authentication required", "please log in", "invalid credentials",
                "401", "403", "error", "failed", "denied"
            ]

            content_lower = content.lower()

            # Check for failure indicators first (more specific)
            if any(indicator in content_lower for indicator in failure_indicators):
                return False

            # Check for success indicators
            return any(indicator in content_lower for indicator in success_indicators)

        except:
            return False
