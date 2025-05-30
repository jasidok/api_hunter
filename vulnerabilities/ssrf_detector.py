"""
SSRF (Server-Side Request Forgery) Detector

Detects vulnerabilities where APIs make server-side requests to URLs
controlled by attackers, potentially allowing access to internal services.
"""

import re
import json
import urllib.parse
from typing import List, Dict, Any, Optional, Set
import aiohttp

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity


class SSRFDetector(BaseVulnerabilityDetector):
    """
    Detector for Server-Side Request Forgery (SSRF) vulnerabilities
    
    SSRF occurs when an API makes requests to URLs controlled by attackers,
    potentially allowing access to internal services or data exfiltration.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        super().__init__(session, config)

        # URL-like parameter patterns
        self.url_patterns = [
            r'url', r'uri', r'link', r'src', r'href', r'callback',
            r'redirect', r'next', r'continue', r'return_to', r'goto',
            r'webhook', r'endpoint', r'api_url', r'service_url',
            r'proxy', r'fetch', r'download', r'upload', r'import'
        ]

        # Internal/localhost targets for SSRF testing
        self.ssrf_payloads = [
            # Localhost variations
            'http://localhost:80',
            'http://127.0.0.1:80',
            'http://0.0.0.0:80',
            'http://[::1]:80',
            'http://localhost:22',
            'http://127.0.0.1:22',
            'http://localhost:3306',
            'http://127.0.0.1:3306',
            'http://localhost:5432',
            'http://127.0.0.1:5432',
            'http://localhost:6379',
            'http://127.0.0.1:6379',
            'http://localhost:8080',
            'http://127.0.0.1:8080',
            'http://localhost:9200',
            'http://127.0.0.1:9200',

            # Internal network ranges
            'http://192.168.1.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
            'http://192.168.0.1:80',
            'http://10.0.0.1:80',
            'http://172.16.0.1:80',

            # Cloud metadata services
            'http://169.254.169.254',
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/computeMetadata/v1/',
            'http://169.254.169.254/metadata/v1/',

            # Protocol bypass attempts
            'file:///etc/passwd',
            'file:///etc/hosts',
            'file:///windows/system32/drivers/etc/hosts',
            'ftp://127.0.0.1',
            'gopher://127.0.0.1:80',
            'dict://127.0.0.1:11211',
            'ldap://127.0.0.1:389',

            # URL encoding bypass
            'http://127.0.0.1%2580',
            'http://127.0.0.1%3A80',
            'http://localhost%2580',
            'http://0x7f000001',
            'http://017700000001',
            'http://2130706433',
        ]

        # Indicators of successful SSRF
        self.ssrf_indicators = [
            # Common error messages indicating internal requests
            r'connection refused',
            r'connection timeout',
            r'no route to host',
            r'network unreachable',
            r'connection reset',
            r'connection aborted',

            # SSH/Service banners
            r'SSH-\d+\.\d+',
            r'openssh',
            r'mysql.*version',
            r'postgresql.*version',
            r'redis.*version',
            r'apache.*server',
            r'nginx.*server',

            # Cloud metadata responses
            r'ami-[a-f0-9]+',
            r'instance-id',
            r'local-hostname',
            r'security-groups',
            r'iam.*role',
            r'access.*key.*id',
            r'secret.*access.*key',
            r'metadata.*token',

            # File contents (for file:// protocol)
            r'root:.*:0:0:',
            r'daemon:.*:1:1:',
            r'127\.0\.0\.1.*localhost',
            r'::1.*localhost',

            # Internal service responses
            r'404.*not found',
            r'403.*forbidden',
            r'401.*unauthorized',
            r'500.*internal.*server.*error',
        ]

    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect SSRF vulnerabilities in the given endpoint
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of SSRF vulnerabilities found
        """
        results = []

        # Test query parameters
        if params:
            results.extend(await self._test_query_params_ssrf(endpoint, method, params, headers, data))

        # Test JSON body parameters
        if data and method in ['POST', 'PUT', 'PATCH']:
            results.extend(await self._test_json_body_ssrf(endpoint, method, data, headers))

        return results

    async def _test_query_params_ssrf(self, endpoint: str, method: str,
                                      params: Dict[str, Any],
                                      headers: Dict[str, str] = None,
                                      data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for SSRF in query parameters"""
        results = []

        # Find URL-like parameters
        url_params = []
        for param_name in params.keys():
            if any(pattern in param_name.lower() for pattern in self.url_patterns):
                url_params.append(param_name)
            # Also check if parameter value looks like a URL
            elif self._looks_like_url(str(params[param_name])):
                url_params.append(param_name)

        if not url_params:
            return results

        # Test each URL parameter with SSRF payloads
        for param_name in url_params:
            for payload in self.ssrf_payloads:
                modified_params = params.copy()
                modified_params[param_name] = payload

                vulnerability = await self._test_ssrf_payload(
                    endpoint, method, payload, param_name, 'query_param',
                    params=modified_params, headers=headers, data=data
                )

                if vulnerability:
                    results.append(vulnerability)

                await self.rate_limit_delay()

        return results

    async def _test_json_body_ssrf(self, endpoint: str, method: str,
                                   data: Dict[str, Any],
                                   headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for SSRF in JSON body parameters"""
        results = []

        # Find URL-like fields in JSON data
        url_fields = []

        def find_url_fields(obj, prefix=''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    if any(pattern in key.lower() for pattern in self.url_patterns):
                        url_fields.append((full_key, key))
                    elif isinstance(value, str) and self._looks_like_url(value):
                        url_fields.append((full_key, key))
                    elif isinstance(value, (dict, list)):
                        find_url_fields(value, full_key)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    find_url_fields(item, f"{prefix}[{i}]")

        find_url_fields(data)

        if not url_fields:
            return results

        # Test each URL field with SSRF payloads
        for full_path, field_name in url_fields:
            # For simplicity, only test top-level fields
            if '.' not in full_path and '[' not in full_path:
                for payload in self.ssrf_payloads:
                    modified_data = data.copy()
                    modified_data[field_name] = payload

                    vulnerability = await self._test_ssrf_payload(
                        endpoint, method, payload, field_name, 'json_body',
                        headers=headers, data=modified_data
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

        return results

    async def _test_ssrf_payload(self, endpoint: str, method: str,
                                 payload: str, param_name: str, location: str,
                                 params: Dict[str, Any] = None,
                                 headers: Dict[str, str] = None,
                                 data: Dict[str, Any] = None) -> Optional[VulnerabilityResult]:
        """Test a specific SSRF payload and analyze the response"""

        response = await self.make_request(endpoint, method, params, headers, data)
        if not response:
            return None

        response_text = getattr(response, '_text', '')

        # Analyze response for SSRF indicators
        vulnerability_indicators = []
        severity = Severity.LOW

        # 1. Check for SSRF indicator patterns in response
        for pattern in self.ssrf_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                vulnerability_indicators.append(f"SSRF indicator detected: {pattern}")
                severity = Severity.HIGH
                break

        # 2. Check response timing (simple heuristic)
        # Note: In a real implementation, we'd measure actual response time
        if response.status == 408 or 'timeout' in response_text.lower():
            vulnerability_indicators.append("Request timeout indicating potential SSRF")
            severity = Severity.MEDIUM

        # 3. Check for connection errors
        connection_errors = [
            'connection refused', 'connection timeout', 'connection reset',
            'network unreachable', 'no route to host', 'connection aborted'
        ]
        for error in connection_errors:
            if error in response_text.lower():
                vulnerability_indicators.append(f"Connection error: {error}")
                severity = Severity.MEDIUM
                break

        # 4. Check for internal service responses
        if self._detect_internal_service_response(response_text, payload):
            vulnerability_indicators.append("Internal service response detected")
            severity = Severity.HIGH

        # 5. Check for cloud metadata access
        if self._detect_cloud_metadata_access(response_text, payload):
            vulnerability_indicators.append("Cloud metadata service access detected")
            severity = Severity.CRITICAL

        # 6. Check for file protocol access
        if self._detect_file_protocol_access(response_text, payload):
            vulnerability_indicators.append("File protocol access detected")
            severity = Severity.HIGH

        # 7. Check for different response when using internal URLs
        if self._detect_different_response_behavior(response, payload):
            vulnerability_indicators.append("Different response behavior for internal URL")
            severity = Severity.MEDIUM

        if not vulnerability_indicators:
            return None

        # Create evidence
        evidence = {
            'ssrf_payload': payload,
            'parameter_name': param_name,
            'location': location,
            'status_code': response.status,
            'indicators': vulnerability_indicators,
            'response_sample': response_text[:1000] if response_text else '',
            'payload_type': self._classify_payload(payload)
        }

        title = f"SSRF Vulnerability in {param_name}"
        description = (
            f"Server-Side Request Forgery vulnerability detected in parameter '{param_name}' "
            f"at {location}. The server made a request to '{payload}'. "
            f"Indicators: {', '.join(vulnerability_indicators)}"
        )

        remediation = (
            "Implement proper URL validation and filtering. Use allowlists for permitted domains and protocols. "
            "Validate and sanitize all user-provided URLs. Consider using a proxy service for external requests. "
            "Block requests to internal/private IP ranges and metadata services."
        )

        return self.create_result(
            vuln_type="SSRF",
            severity=severity,
            title=title,
            description=description,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            remediation=remediation,
            cwe_id="CWE-918",
            owasp_category="API10:2023 Unsafe Consumption of APIs"
        )

    def _looks_like_url(self, value: str) -> bool:
        """Check if a value looks like a URL"""
        if not isinstance(value, str):
            return False

        # Basic URL pattern matching
        url_patterns = [
            r'^https?://',
            r'^ftp://',
            r'^file://',
            r'://.*\.',
            r'www\.',
        ]

        for pattern in url_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True

        return False

    def _detect_internal_service_response(self, response_text: str, payload: str) -> bool:
        """Detect responses indicating access to internal services"""
        # SSH service banners
        if re.search(r'SSH-\d+\.\d+', response_text):
            return True

        # Database service responses
        db_indicators = [
            r'mysql.*version',
            r'postgresql.*server',
            r'redis.*server',
            r'mongodb.*server'
        ]
        for indicator in db_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True

        # Web server responses from internal services
        if 'localhost' in payload or '127.0.0.1' in payload:
            web_indicators = [
                r'apache.*server',
                r'nginx.*server',
                r'iis.*server',
                r'server:.*apache',
                r'server:.*nginx'
            ]
            for indicator in web_indicators:
                if re.search(indicator, response_text, re.IGNORECASE):
                    return True

        return False

    def _detect_cloud_metadata_access(self, response_text: str, payload: str) -> bool:
        """Detect access to cloud metadata services"""
        if '169.254.169.254' not in payload:
            return False

        metadata_indicators = [
            r'ami-[a-f0-9]+',
            r'instance-id',
            r'local-hostname',
            r'security-groups',
            r'iam.*role',
            r'access.*key.*id',
            r'secret.*access.*key',
            r'session.*token',
            r'metadata.*token'
        ]

        for indicator in metadata_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True

        return False

    def _detect_file_protocol_access(self, response_text: str, payload: str) -> bool:
        """Detect successful file protocol access"""
        if not payload.startswith('file://'):
            return False

        file_indicators = [
            r'root:.*:0:0:',  # /etc/passwd content
            r'daemon:.*:1:1:',
            r'127\.0\.0\.1.*localhost',  # /etc/hosts content
            r'::1.*localhost',
            r'\[hosts\]',  # Windows hosts file
            r'# Copyright.*Microsoft'
        ]

        for indicator in file_indicators:
            if re.search(indicator, response_text):
                return True

        return False

    def _detect_different_response_behavior(self, response: aiohttp.ClientResponse,
                                            payload: str) -> bool:
        """Detect different response behavior indicating SSRF"""
        # This is a simplified check - in practice, you'd compare with baseline responses

        # Different status codes for internal vs external URLs
        if ('localhost' in payload or '127.0.0.1' in payload or '169.254.169.254' in payload):
            # Internal URLs might return different status codes
            if response.status in [200, 302, 403, 404]:
                return True

        # Response contains error messages specific to internal network issues
        response_text = getattr(response, '_text', '')
        internal_error_patterns = [
            r'connection.*refused',
            r'connection.*timeout',
            r'network.*unreachable',
            r'host.*unreachable'
        ]

        for pattern in internal_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _classify_payload(self, payload: str) -> str:
        """Classify the type of SSRF payload"""
        if payload.startswith('file://'):
            return 'file_protocol'
        elif '169.254.169.254' in payload:
            return 'cloud_metadata'
        elif any(host in payload for host in ['localhost', '127.0.0.1', '0.0.0.0']):
            return 'localhost'
        elif any(net in payload for net in ['192.168.', '10.0.', '172.16.']):
            return 'internal_network'
        elif payload.startswith(('gopher://', 'dict://', 'ldap://', 'ftp://')):
            return 'protocol_bypass'
        else:
            return 'generic'
