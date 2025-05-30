"""
Session Security Analyzer

Comprehensive session management security testing including session fixation,
hijacking, and cookie security analysis.
"""

from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass
import logging
import asyncio
import re
import time
from urllib.parse import urlparse

import httpx

from ..core.http_client import HTTPClient
from ..core.models import Vulnerability
from .auth_manager import AuthCredentials


class SessionVulnerabilityType(Enum):
    """Session vulnerability types"""
    SESSION_FIXATION = "session_fixation"
    SESSION_HIJACKING = "session_hijacking"
    WEAK_SESSION_ID = "weak_session_id"
    MISSING_SECURE_FLAG = "missing_secure_flag"
    MISSING_HTTPONLY_FLAG = "missing_httponly_flag"
    MISSING_SAMESITE = "missing_samesite"
    LONG_SESSION_TIMEOUT = "long_session_timeout"
    SESSION_PREDICTION = "session_prediction"


class SessionAnalyzer:
    """Session security testing and analysis"""

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.logger = logging.getLogger(__name__)

    async def analyze_session_security(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Comprehensive session security analysis"""
        vulnerabilities = []

        try:
            # Analyze session cookies
            cookie_vulns = await self._analyze_session_cookies(credentials)
            vulnerabilities.extend(cookie_vulns)

            # Test session fixation
            fixation_vulns = await self._test_session_fixation(credentials)
            vulnerabilities.extend(fixation_vulns)

            # Test session ID strength
            strength_vulns = await self._test_session_id_strength(credentials)
            vulnerabilities.extend(strength_vulns)

            # Test session timeout
            timeout_vulns = await self._test_session_timeout(credentials)
            vulnerabilities.extend(timeout_vulns)

            # Test session prediction
            prediction_vulns = await self._test_session_prediction(credentials)
            vulnerabilities.extend(prediction_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error analyzing session security: {e}")
            return []

    async def _analyze_session_cookies(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Analyze session cookie security attributes"""
        vulnerabilities = []

        try:
            # Make a request to get session cookies
            response = await self.http_client.get("/")

            if not response:
                return vulnerabilities

            # Analyze all cookies
            for cookie_header in response.headers.get_list('set-cookie'):
                vulnerabilities.extend(self._analyze_cookie_attributes(cookie_header))

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error analyzing session cookies: {e}")
            return []

    def _analyze_cookie_attributes(self, cookie_header: str) -> List[Vulnerability]:
        """Analyze individual cookie attributes"""
        vulnerabilities = []

        try:
            # Parse cookie name and value
            cookie_parts = cookie_header.split(';')
            cookie_name_value = cookie_parts[0].strip()
            cookie_name = cookie_name_value.split('=')[0]

            # Skip non-session cookies
            session_indicators = ['session', 'sess', 'auth', 'token', 'login', 'jsession']
            if not any(indicator in cookie_name.lower() for indicator in session_indicators):
                return vulnerabilities

            cookie_attributes = {}
            for part in cookie_parts[1:]:
                if '=' in part:
                    key, value = part.strip().split('=', 1)
                    cookie_attributes[key.lower()] = value
                else:
                    cookie_attributes[part.strip().lower()] = True

            # Check for Secure flag
            if 'secure' not in cookie_attributes:
                vuln = Vulnerability(
                    vuln_type="SESSION_MISSING_SECURE_FLAG",
                    severity="Medium",
                    title="Session Cookie Missing Secure Flag",
                    description=f"Session cookie '{cookie_name}' is missing the Secure flag",
                    evidence={
                        "cookie_name": cookie_name,
                        "cookie_header": cookie_header
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            # Check for HttpOnly flag
            if 'httponly' not in cookie_attributes:
                vuln = Vulnerability(
                    vuln_type="SESSION_MISSING_HTTPONLY_FLAG",
                    severity="Medium",
                    title="Session Cookie Missing HttpOnly Flag",
                    description=f"Session cookie '{cookie_name}' is missing the HttpOnly flag",
                    evidence={
                        "cookie_name": cookie_name,
                        "cookie_header": cookie_header
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            # Check for SameSite attribute
            if 'samesite' not in cookie_attributes:
                vuln = Vulnerability(
                    vuln_type="SESSION_MISSING_SAMESITE",
                    severity="Low",
                    title="Session Cookie Missing SameSite Attribute",
                    description=f"Session cookie '{cookie_name}' is missing the SameSite attribute",
                    evidence={
                        "cookie_name": cookie_name,
                        "cookie_header": cookie_header
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)
            elif cookie_attributes.get('samesite', '').lower() == 'none':
                vuln = Vulnerability(
                    vuln_type="SESSION_WEAK_SAMESITE",
                    severity="Medium",
                    title="Session Cookie Weak SameSite Setting",
                    description=f"Session cookie '{cookie_name}' has SameSite=None",
                    evidence={
                        "cookie_name": cookie_name,
                        "samesite_value": cookie_attributes['samesite']
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            # Check for overly long expiration
            if 'max-age' in cookie_attributes:
                max_age = int(cookie_attributes['max-age'])
                if max_age > 86400 * 30:  # 30 days
                    vuln = Vulnerability(
                        vuln_type="SESSION_LONG_EXPIRATION",
                        severity="Low",
                        title="Session Cookie Long Expiration",
                        description=f"Session cookie expires in {max_age} seconds ({max_age // 86400} days)",
                        evidence={
                            "cookie_name": cookie_name,
                            "max_age": max_age
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error analyzing cookie attributes: {e}")
            return []

    async def _test_session_fixation(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Test for session fixation vulnerabilities"""
        vulnerabilities = []

        try:
            # Get initial session before authentication
            initial_response = await self.http_client.get("/")
            initial_cookies = self._extract_session_cookies(initial_response)

            # Attempt login with pre-existing session
            login_data = {
                "username": "test_user",
                "password": "test_password"
            }

            login_response = await self.http_client.post(
                "/login",
                data=login_data,
                cookies=initial_cookies
            )

            if login_response and login_response.status_code in [200, 302]:
                # Check if session ID remained the same
                post_login_cookies = self._extract_session_cookies(login_response)

                for cookie_name, initial_value in initial_cookies.items():
                    if cookie_name in post_login_cookies:
                        if initial_value == post_login_cookies[cookie_name]:
                            vuln = Vulnerability(
                                vuln_type="SESSION_FIXATION",
                                severity="High",
                                title="Session Fixation Vulnerability",
                                description=f"Session ID '{cookie_name}' remained unchanged after authentication",
                                evidence={
                                    "cookie_name": cookie_name,
                                    "session_id": initial_value[:8] + "..."
                                },
                                endpoint="/login"
                            )
                            vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing session fixation: {e}")
            return []

    async def _test_session_id_strength(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Test session ID strength and randomness"""
        vulnerabilities = []

        try:
            # Collect multiple session IDs
            session_ids = []

            for _ in range(10):
                response = await self.http_client.get("/")
                if response:
                    cookies = self._extract_session_cookies(response)
                    for cookie_name, cookie_value in cookies.items():
                        session_ids.append((cookie_name, cookie_value))

                await asyncio.sleep(0.5)

            # Analyze session ID patterns
            for cookie_name, session_id in session_ids:
                # Check length
                if len(session_id) < 16:
                    vuln = Vulnerability(
                        vuln_type="SESSION_WEAK_ID_LENGTH",
                        severity="Medium",
                        title="Weak Session ID Length",
                        description=f"Session ID '{cookie_name}' is too short ({len(session_id)} characters)",
                        evidence={
                            "cookie_name": cookie_name,
                            "length": len(session_id),
                            "session_id": session_id[:8] + "..."
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

                # Check for predictable patterns
                if self._has_predictable_pattern(session_id):
                    vuln = Vulnerability(
                        vuln_type="SESSION_PREDICTABLE_PATTERN",
                        severity="High",
                        title="Predictable Session ID Pattern",
                        description=f"Session ID '{cookie_name}' has predictable patterns",
                        evidence={
                            "cookie_name": cookie_name,
                            "session_id": session_id[:8] + "..."
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

                # Check entropy
                entropy = self._calculate_entropy(session_id)
                if entropy < 3.0:
                    vuln = Vulnerability(
                        vuln_type="SESSION_LOW_ENTROPY",
                        severity="High",
                        title="Session ID Low Entropy",
                        description=f"Session ID has low entropy ({entropy:.2f})",
                        evidence={
                            "cookie_name": cookie_name,
                            "entropy": entropy,
                            "session_id": session_id[:8] + "..."
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing session ID strength: {e}")
            return []

    async def _test_session_timeout(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Test session timeout behavior"""
        vulnerabilities = []

        try:
            # Make authenticated request
            auth_response = await self.http_client.get(
                "/",
                headers={"Authorization": f"Bearer {credentials.value}"}
            )

            if not auth_response or auth_response.status_code != 200:
                return vulnerabilities

            # Wait for a reasonable timeout period (simulate user inactivity)
            await asyncio.sleep(300)  # 5 minutes

            # Test if session is still valid
            timeout_response = await self.http_client.get(
                "/profile",  # Authenticated endpoint
                headers={"Authorization": f"Bearer {credentials.value}"}
            )

            if timeout_response and timeout_response.status_code == 200:
                vuln = Vulnerability(
                    vuln_type="SESSION_NO_TIMEOUT",
                    severity="Medium",
                    title="Session Does Not Timeout",
                    description="Session remained valid after 5 minutes of inactivity",
                    evidence={
                        "timeout_duration": "300 seconds",
                        "still_valid": True
                    },
                    endpoint="/profile"
                )
                vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing session timeout: {e}")
            return []

    async def _test_session_prediction(self, credentials: AuthCredentials) -> List[Vulnerability]:
        """Test for session ID prediction vulnerabilities"""
        vulnerabilities = []

        try:
            # Collect sequential session IDs
            session_ids = []
            timestamps = []

            for _ in range(5):
                timestamp = time.time()
                response = await self.http_client.get("/")

                if response:
                    cookies = self._extract_session_cookies(response)
                    for cookie_name, cookie_value in cookies.items():
                        session_ids.append(cookie_value)
                        timestamps.append(timestamp)

                await asyncio.sleep(1)

            # Analyze for sequential patterns
            if len(session_ids) >= 3:
                for i in range(len(session_ids) - 2):
                    id1, id2, id3 = session_ids[i:i + 3]

                    # Check if IDs are sequential (for numeric IDs)
                    if self._are_sequential(id1, id2, id3):
                        vuln = Vulnerability(
                            vuln_type="SESSION_SEQUENTIAL_IDS",
                            severity="Critical",
                            title="Sequential Session IDs",
                            description="Session IDs follow a predictable sequential pattern",
                            evidence={
                                "sequential_ids": [id1[:8] + "...", id2[:8] + "...", id3[:8] + "..."],
                                "pattern": "sequential"
                            },
                            endpoint="N/A"
                        )
                        vulnerabilities.append(vuln)

                    # Check for timestamp-based patterns
                    if self._is_timestamp_based(id1, timestamps[i]):
                        vuln = Vulnerability(
                            vuln_type="SESSION_TIMESTAMP_BASED",
                            severity="High",
                            title="Timestamp-Based Session IDs",
                            description="Session IDs appear to be based on timestamps",
                            evidence={
                                "session_id": id1[:8] + "...",
                                "timestamp": timestamps[i],
                                "pattern": "timestamp-based"
                            },
                            endpoint="N/A"
                        )
                        vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing session prediction: {e}")
            return []

    def _extract_session_cookies(self, response: httpx.Response) -> Dict[str, str]:
        """Extract session cookies from response"""
        cookies = {}

        try:
            session_indicators = ['session', 'sess', 'auth', 'token', 'login', 'jsession']

            for cookie_header in response.headers.get_list('set-cookie'):
                cookie_parts = cookie_header.split(';')
                cookie_name_value = cookie_parts[0].strip()

                if '=' in cookie_name_value:
                    name, value = cookie_name_value.split('=', 1)

                    # Check if this is likely a session cookie
                    if any(indicator in name.lower() for indicator in session_indicators):
                        cookies[name] = value

            return cookies

        except Exception as e:
            self.logger.error(f"Error extracting session cookies: {e}")
            return {}

    def _has_predictable_pattern(self, session_id: str) -> bool:
        """Check if session ID has predictable patterns"""
        try:
            # Check for common patterns
            patterns = [
                r'^\d+$',  # Only digits
                r'^[a-f0-9]+$',  # Only hex (but might be MD5/SHA)
                r'^(test|demo|admin|user)',  # Predictable prefixes
                r'(123|abc|000|111|aaa)',  # Repeated patterns
                r'^.{8}-.{4}-.{4}-.{4}-.{12}$'  # UUID format (not always predictable but often weak)
            ]

            for pattern in patterns:
                if re.match(pattern, session_id.lower()):
                    return True

            # Check for repeated characters
            if len(set(session_id)) < len(session_id) * 0.5:
                return True

            return False

        except:
            return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        try:
            import math
            from collections import Counter

            counter = Counter(text)
            length = len(text)

            entropy = 0.0
            for count in counter.values():
                probability = count / length
                entropy -= probability * math.log2(probability)

            return entropy

        except:
            return 0.0

    def _are_sequential(self, id1: str, id2: str, id3: str) -> bool:
        """Check if session IDs are sequential"""
        try:
            # Try to convert to integers and check sequence
            num1, num2, num3 = int(id1), int(id2), int(id3)
            return (num2 == num1 + 1) and (num3 == num2 + 1)
        except ValueError:
            # Try hex conversion
            try:
                num1 = int(id1, 16)
                num2 = int(id2, 16)
                num3 = int(id3, 16)
                return (num2 == num1 + 1) and (num3 == num2 + 1)
            except ValueError:
                return False

    def _is_timestamp_based(self, session_id: str, timestamp: float) -> bool:
        """Check if session ID is based on timestamp"""
        try:
            # Check if session ID contains timestamp
            timestamp_int = int(timestamp)

            # Check various timestamp formats
            timestamp_formats = [
                str(timestamp_int),  # Unix timestamp
                str(timestamp_int * 1000),  # Milliseconds
                hex(timestamp_int)[2:],  # Hex timestamp
            ]

            for ts_format in timestamp_formats:
                if ts_format in session_id:
                    return True

            return False

        except:
            return False
