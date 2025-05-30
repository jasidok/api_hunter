"""
Token Brute Forcer

Comprehensive token and secret brute forcing for JWT secrets, API keys,
and other authentication tokens.
"""

from typing import Dict, List, Optional, Any
from enum import Enum
import logging
import asyncio
import hashlib
import hmac
import base64
import json
import secrets
import string

import jwt

from ..core.http_client import HTTPClient
from ..core.models import Vulnerability
from .auth_manager import AuthType


class TokenBruteforcer:
    """Token and secret brute forcing"""

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.logger = logging.getLogger(__name__)

        # Common weak secrets for JWT
        self.jwt_weak_secrets = [
            "secret", "password", "123456", "admin", "test", "key",
            "jwt", "token", "auth", "api", "default", "changeme",
            "HS256", "HS384", "HS512", "RS256", "your-256-bit-secret",
            "your-secret-key", "my-secret", "super-secret", "",
            "development", "production", "staging", "localhost",
            "app_secret", "jwt_secret", "signing_key", "private_key",
            "public_key", "master_key", "session_secret", "cookie_secret"
        ]

        # Extended wordlist
        self.extended_wordlist = [
            # Common passwords
            "password", "123456", "123456789", "qwerty", "abc123",
            "password123", "admin", "letmein", "welcome", "monkey",
            "dragon", "princess", "football", "baseball", "superman",

            # Common application terms
            "secret", "key", "token", "auth", "api", "jwt", "session",
            "login", "user", "admin", "root", "guest", "test", "demo",

            # Company/app specific
            "company", "app", "application", "service", "server",
            "development", "staging", "production", "live", "backup",

            # Technical terms
            "crypto", "hash", "salt", "pepper", "secure", "private",
            "public", "rsa", "hmac", "sha256", "md5", "aes"
        ]

    async def brute_force_secrets(self, auth_type: AuthType, sample_token: str,
                                  wordlist_path: Optional[str] = None) -> List[Vulnerability]:
        """Brute force authentication secrets"""
        vulnerabilities = []

        try:
            if auth_type == AuthType.JWT:
                jwt_vulns = await self._brute_force_jwt_secret(sample_token, wordlist_path)
                vulnerabilities.extend(jwt_vulns)

            elif auth_type == AuthType.API_KEY:
                api_vulns = await self._brute_force_api_key(sample_token)
                vulnerabilities.extend(api_vulns)

            elif auth_type == AuthType.SESSION:
                session_vulns = await self._brute_force_session_secret(sample_token)
                vulnerabilities.extend(session_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error brute forcing secrets: {e}")
            return []

    async def _brute_force_jwt_secret(self, jwt_token: str,
                                      wordlist_path: Optional[str] = None) -> List[Vulnerability]:
        """Brute force JWT HMAC secrets"""
        vulnerabilities = []

        try:
            # Parse JWT to get algorithm
            try:
                header = jwt.get_unverified_header(jwt_token)
                algorithm = header.get('alg', '').upper()
            except Exception:
                return vulnerabilities

            # Only brute force HMAC algorithms
            if not algorithm.startswith('HS'):
                return vulnerabilities

            # Load wordlist
            wordlist = self.jwt_weak_secrets.copy()

            if wordlist_path:
                try:
                    with open(wordlist_path, 'r') as f:
                        wordlist.extend([line.strip() for line in f if line.strip()])
                except FileNotFoundError:
                    self.logger.warning(f"Wordlist file not found: {wordlist_path}")

            # Add extended wordlist
            wordlist.extend(self.extended_wordlist)

            # Remove duplicates
            wordlist = list(set(wordlist))

            self.logger.info(f"Brute forcing JWT secret with {len(wordlist)} candidates")

            # Test each secret
            for i, secret in enumerate(wordlist):
                try:
                    # Attempt to decode with this secret
                    decoded = jwt.decode(jwt_token, secret, algorithms=[algorithm])

                    # If successful, we found the secret
                    vuln = Vulnerability(
                        vuln_type="JWT_SECRET_CRACKED",
                        severity="Critical",
                        title="JWT Secret Successfully Brute Forced",
                        description=f"JWT secret cracked: '{secret}' (algorithm: {algorithm})",
                        evidence={
                            "cracked_secret": secret,
                            "algorithm": algorithm,
                            "decoded_payload": decoded,
                            "attempts": i + 1
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)

                    self.logger.info(f"JWT secret found: {secret}")
                    break

                except jwt.InvalidTokenError:
                    continue

                # Rate limiting to avoid overwhelming
                if i % 100 == 0:
                    await asyncio.sleep(0.1)
                    if i > 0:
                        self.logger.info(f"Tested {i} secrets so far...")

            # Test with common variations if no secret found
            if not vulnerabilities:
                variation_vulns = await self._test_jwt_secret_variations(jwt_token, algorithm)
                vulnerabilities.extend(variation_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error brute forcing JWT secret: {e}")
            return []

    async def _test_jwt_secret_variations(self, jwt_token: str,
                                          algorithm: str) -> List[Vulnerability]:
        """Test JWT secret variations and patterns"""
        vulnerabilities = []

        try:
            # Extract payload to look for clues
            try:
                payload = jwt.decode(jwt_token, options={"verify_signature": False})
            except Exception:
                payload = {}

            # Generate variations based on payload content
            variations = set()

            # Add issuer-based secrets
            if 'iss' in payload:
                issuer = payload['iss']
                variations.update([
                    issuer, f"{issuer}_secret", f"{issuer}_key",
                    f"secret_{issuer}", f"key_{issuer}"
                ])

            # Add audience-based secrets
            if 'aud' in payload:
                audience = payload['aud']
                if isinstance(audience, str):
                    variations.update([
                        audience, f"{audience}_secret", f"{audience}_key",
                        f"secret_{audience}", f"key_{audience}"
                    ])

            # Add subject-based secrets
            if 'sub' in payload:
                subject = payload['sub']
                variations.update([
                    subject, f"{subject}_secret", f"{subject}_key"
                ])

            # Add algorithm-based secrets
            variations.update([
                algorithm.lower(), algorithm, f"{algorithm}_secret",
                f"secret_{algorithm.lower()}", f"key_{algorithm.lower()}"
            ])

            # Test variations
            for secret in variations:
                try:
                    decoded = jwt.decode(jwt_token, secret, algorithms=[algorithm])

                    vuln = Vulnerability(
                        vuln_type="JWT_SECRET_PATTERN_CRACKED",
                        severity="Critical",
                        title="JWT Secret Cracked via Pattern Analysis",
                        description=f"JWT secret found using pattern: '{secret}'",
                        evidence={
                            "cracked_secret": secret,
                            "algorithm": algorithm,
                            "decoded_payload": decoded,
                            "pattern_type": "payload_analysis"
                        },
                        endpoint="N/A"
                    )
                    vulnerabilities.append(vuln)
                    break

                except jwt.InvalidTokenError:
                    continue

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error testing JWT secret variations: {e}")
            return []

    async def _brute_force_api_key(self, api_key: str) -> List[Vulnerability]:
        """Brute force API key patterns"""
        vulnerabilities = []

        try:
            # Analyze API key structure
            key_length = len(api_key)
            key_charset = set(api_key)

            # Check if key follows common patterns
            patterns_found = []

            # Check for UUID pattern
            if len(api_key) == 36 and api_key.count('-') == 4:
                patterns_found.append("UUID")

            # Check for hex pattern
            if all(c in '0123456789abcdefABCDEF' for c in api_key):
                patterns_found.append("Hexadecimal")

            # Check for base64 pattern
            try:
                base64.b64decode(api_key + '==')
                patterns_found.append("Base64")
            except:
                pass

            # Check for predictable patterns
            predictable_issues = []

            # Sequential characters
            if self._has_sequential_chars(api_key):
                predictable_issues.append("Contains sequential characters")

            # Repeated patterns
            if self._has_repeated_patterns(api_key):
                predictable_issues.append("Contains repeated patterns")

            # Dictionary words
            dict_words = self._find_dictionary_words(api_key)
            if dict_words:
                predictable_issues.append(f"Contains dictionary words: {', '.join(dict_words)}")

            # Report vulnerabilities
            if predictable_issues:
                vuln = Vulnerability(
                    vuln_type="API_KEY_PREDICTABLE_STRUCTURE",
                    severity="Medium",
                    title="API Key Has Predictable Structure",
                    description=f"API key shows predictable patterns: {'; '.join(predictable_issues)}",
                    evidence={
                        "api_key_length": key_length,
                        "charset_size": len(key_charset),
                        "patterns": patterns_found,
                        "predictable_issues": predictable_issues
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            # Test common API key generation patterns
            if self._test_timestamp_based(api_key):
                vuln = Vulnerability(
                    vuln_type="API_KEY_TIMESTAMP_BASED",
                    severity="High",
                    title="API Key Appears Timestamp-Based",
                    description="API key appears to contain timestamp information",
                    evidence={
                        "api_key_sample": api_key[:8] + "...",
                        "pattern": "timestamp_based"
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error brute forcing API key: {e}")
            return []

    async def _brute_force_session_secret(self, session_token: str) -> List[Vulnerability]:
        """Brute force session secrets"""
        vulnerabilities = []

        try:
            # Check if session token is signed (contains signature)
            if '.' in session_token or '|' in session_token:
                # Likely signed session - try to crack signature
                signature_vulns = await self._crack_session_signature(session_token)
                vulnerabilities.extend(signature_vulns)

            # Check session token entropy and patterns
            entropy_vulns = await self._analyze_session_entropy(session_token)
            vulnerabilities.extend(entropy_vulns)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error brute forcing session secret: {e}")
            return []

    async def _crack_session_signature(self, session_token: str) -> List[Vulnerability]:
        """Attempt to crack session signature"""
        vulnerabilities = []

        try:
            # Try common separators
            separators = ['.', '|', '--', ':', ';']

            for sep in separators:
                if sep in session_token:
                    parts = session_token.split(sep)
                    if len(parts) >= 2:
                        data = sep.join(parts[:-1])
                        signature = parts[-1]

                        # Try to crack the signature
                        for secret in self.jwt_weak_secrets[:50]:  # Limit to avoid too many requests
                            # Test HMAC-SHA256
                            expected_sig = hmac.new(
                                secret.encode(),
                                data.encode(),
                                hashlib.sha256
                            ).hexdigest()

                            if expected_sig == signature or expected_sig[:len(signature)] == signature:
                                vuln = Vulnerability(
                                    vuln_type="SESSION_SECRET_CRACKED",
                                    severity="Critical",
                                    title="Session Signature Secret Cracked",
                                    description=f"Session signing secret found: '{secret}'",
                                    evidence={
                                        "cracked_secret": secret,
                                        "signature_algorithm": "HMAC-SHA256",
                                        "separator": sep
                                    },
                                    endpoint="N/A"
                                )
                                vulnerabilities.append(vuln)
                                return vulnerabilities

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error cracking session signature: {e}")
            return []

    async def _analyze_session_entropy(self, session_token: str) -> List[Vulnerability]:
        """Analyze session token entropy"""
        vulnerabilities = []

        try:
            import math
            from collections import Counter

            # Calculate entropy
            counter = Counter(session_token)
            length = len(session_token)

            entropy = 0.0
            for count in counter.values():
                probability = count / length
                entropy -= probability * math.log2(probability)

            if entropy < 3.0:
                vuln = Vulnerability(
                    vuln_type="SESSION_TOKEN_LOW_ENTROPY",
                    severity="High",
                    title="Session Token Low Entropy",
                    description=f"Session token has low entropy ({entropy:.2f})",
                    evidence={
                        "entropy": entropy,
                        "token_length": length,
                        "unique_chars": len(counter)
                    },
                    endpoint="N/A"
                )
                vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error(f"Error analyzing session entropy: {e}")
            return []

    def _has_sequential_chars(self, text: str) -> bool:
        """Check for sequential characters"""
        sequential_count = 0
        for i in range(len(text) - 2):
            if ord(text[i + 1]) == ord(text[i]) + 1 and ord(text[i + 2]) == ord(text[i + 1]) + 1:
                sequential_count += 1

        return sequential_count >= 2

    def _has_repeated_patterns(self, text: str) -> bool:
        """Check for repeated patterns"""
        # Check for repeated substrings
        for length in [2, 3, 4]:
            for i in range(len(text) - length * 2 + 1):
                pattern = text[i:i + length]
                if pattern in text[i + length:]:
                    return True

        # Check for repeated characters
        from collections import Counter
        counter = Counter(text)
        most_common_count = counter.most_common(1)[0][1] if counter else 0

        return most_common_count > len(text) * 0.3

    def _find_dictionary_words(self, text: str) -> List[str]:
        """Find dictionary words in text"""
        common_words = [
            'admin', 'user', 'test', 'demo', 'api', 'key', 'token',
            'secret', 'password', 'auth', 'login', 'session', 'app'
        ]

        found_words = []
        text_lower = text.lower()

        for word in common_words:
            if word in text_lower:
                found_words.append(word)

        return found_words

    def _test_timestamp_based(self, text: str) -> bool:
        """Test if text contains timestamp"""
        import time

        current_time = int(time.time())

        # Check for Unix timestamp (various lengths)
        for length in [10, 13, 16]:  # seconds, milliseconds, microseconds
            for i in range(len(text) - length + 1):
                try:
                    potential_timestamp = int(text[i:i + length])

                    # Check if it's a reasonable timestamp (last 20 years to next 5 years)
                    if length == 10:  # seconds
                        if 1000000000 <= potential_timestamp <= current_time + 157680000:  # +5 years
                            return True
                    elif length == 13:  # milliseconds
                        if 1000000000000 <= potential_timestamp <= (current_time + 157680000) * 1000:
                            return True

                except ValueError:
                    continue

        return False
