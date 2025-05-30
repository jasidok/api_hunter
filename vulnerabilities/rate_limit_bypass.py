"""
Rate Limit Bypass Detector

Detects techniques that can be used to bypass rate limiting mechanisms
in APIs, allowing attackers to exceed intended request limits.
"""

import asyncio
import time
from typing import List, Dict, Any, Optional, Set
import aiohttp

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity


class RateLimitBypassDetector(BaseVulnerabilityDetector):
    """
    Detector for Rate Limit Bypass vulnerabilities
    
    Tests various techniques that attackers use to bypass rate limiting
    including header manipulation, IP spoofing, and request variation.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        super().__init__(session, config)

        # Rate limit bypass headers
        self.bypass_headers = {
            'X-Forwarded-For': ['127.0.0.1', '10.0.0.1', '192.168.1.1'],
            'X-Real-IP': ['127.0.0.1', '10.0.0.1', '192.168.1.1'],
            'X-Originating-IP': ['127.0.0.1', '10.0.0.1', '192.168.1.1'],
            'X-Remote-IP': ['127.0.0.1', '10.0.0.1', '192.168.1.1'],
            'X-Client-IP': ['127.0.0.1', '10.0.0.1', '192.168.1.1'],
            'X-Forwarded-Host': ['localhost', 'internal.example.com'],
            'X-Cluster-Client-IP': ['127.0.0.1', '10.0.0.1'],
            'CF-Connecting-IP': ['127.0.0.1', '10.0.0.1'],
            'True-Client-IP': ['127.0.0.1', '10.0.0.1'],
            'X-Azure-ClientIP': ['127.0.0.1', '10.0.0.1'],
            'X-ProxyUser-IP': ['127.0.0.1', '10.0.0.1'],
        }

        # User-Agent variations
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0',
            'PostmanRuntime/7.28.0',
            'python-requests/2.25.1',
        ]

        # Request variation techniques
        self.request_variations = [
            {'technique': 'case_variation', 'description': 'URL case variation'},
            {'technique': 'slash_variation', 'description': 'Trailing slash variation'},
            {'technique': 'parameter_order', 'description': 'Parameter order variation'},
            {'technique': 'encoding_variation', 'description': 'URL encoding variation'},
        ]

        # Number of requests to test rate limiting
        self.test_request_count = 10
        self.rapid_request_count = 5

    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect rate limit bypass vulnerabilities in the given endpoint
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of rate limit bypass vulnerabilities found
        """
        results = []

        # First, establish baseline rate limiting behavior
        baseline_behavior = await self._establish_baseline_rate_limiting(endpoint, method, params, headers, data)

        if not baseline_behavior['has_rate_limiting']:
            # No rate limiting detected, can't test bypasses
            return results

        # Test header-based bypasses
        results.extend(await self._test_header_bypass(endpoint, method, params, headers, data, baseline_behavior))

        # Test User-Agent bypass
        results.extend(await self._test_user_agent_bypass(endpoint, method, params, headers, data, baseline_behavior))

        # Test request variation bypasses
        results.extend(
            await self._test_request_variation_bypass(endpoint, method, params, headers, data, baseline_behavior))

        return results

    async def _establish_baseline_rate_limiting(self, endpoint: str, method: str,
                                                params: Dict[str, Any] = None,
                                                headers: Dict[str, str] = None,
                                                data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Establish baseline rate limiting behavior"""
        baseline = {
            'has_rate_limiting': False,
            'rate_limit_status_code': None,
            'rate_limit_headers': {},
            'requests_before_limit': 0,
            'reset_time': None
        }

        successful_requests = 0
        start_time = time.time()

        for i in range(self.test_request_count):
            response = await self.make_request(endpoint, method, params, headers, data)

            if not response:
                break

            # Check for rate limiting indicators
            if response.status in [429, 503]:
                baseline['has_rate_limiting'] = True
                baseline['rate_limit_status_code'] = response.status
                baseline['requests_before_limit'] = successful_requests

                # Check for rate limit headers
                rate_limit_headers = {}
                for header_name, header_value in response.headers.items():
                    if any(rl_header in header_name.lower() for rl_header in
                           ['rate-limit', 'x-ratelimit', 'retry-after', 'x-rate-limit']):
                        rate_limit_headers[header_name] = header_value

                baseline['rate_limit_headers'] = rate_limit_headers
                break

            elif response.status == 200:
                successful_requests += 1

            await asyncio.sleep(0.1)  # Small delay between requests

        return baseline

    async def _test_header_bypass(self, endpoint: str, method: str,
                                  params: Dict[str, Any] = None,
                                  headers: Dict[str, str] = None,
                                  data: Dict[str, Any] = None,
                                  baseline: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test rate limit bypass using IP spoofing headers"""
        results = []

        base_headers = headers.copy() if headers else {}

        for header_name, header_values in self.bypass_headers.items():
            for header_value in header_values:
                test_headers = base_headers.copy()
                test_headers[header_name] = header_value

                # Rapidly send requests to trigger rate limiting
                bypass_successful = await self._test_rapid_requests(
                    endpoint, method, params, test_headers, data, baseline
                )

                if bypass_successful:
                    evidence = {
                        'bypass_technique': 'header_spoofing',
                        'bypass_header': header_name,
                        'bypass_value': header_value,
                        'baseline_limit': baseline['requests_before_limit'],
                        'test_description': f'Rate limit bypassed using {header_name}: {header_value}'
                    }

                    vulnerability = self.create_result(
                        vuln_type="Rate Limit Bypass",
                        severity=Severity.MEDIUM,
                        title=f"Rate Limit Bypass via {header_name} Header",
                        description=f"Rate limiting can be bypassed by setting the {header_name} header to {header_value}",
                        endpoint=endpoint,
                        method=method,
                        evidence=evidence,
                        remediation=f"Implement proper IP validation and don't trust {header_name} header for rate limiting",
                        cwe_id="CWE-770",
                        owasp_category="API4:2023 Unrestricted Resource Consumption"
                    )
                    results.append(vulnerability)

                await asyncio.sleep(1)  # Wait between tests

        return results

    async def _test_user_agent_bypass(self, endpoint: str, method: str,
                                      params: Dict[str, Any] = None,
                                      headers: Dict[str, str] = None,
                                      data: Dict[str, Any] = None,
                                      baseline: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test rate limit bypass using different User-Agent headers"""
        results = []

        base_headers = headers.copy() if headers else {}

        for user_agent in self.user_agents:
            test_headers = base_headers.copy()
            test_headers['User-Agent'] = user_agent

            bypass_successful = await self._test_rapid_requests(
                endpoint, method, params, test_headers, data, baseline
            )

            if bypass_successful:
                evidence = {
                    'bypass_technique': 'user_agent_variation',
                    'user_agent': user_agent,
                    'baseline_limit': baseline['requests_before_limit'],
                    'test_description': f'Rate limit bypassed using User-Agent: {user_agent}'
                }

                vulnerability = self.create_result(
                    vuln_type="Rate Limit Bypass",
                    severity=Severity.LOW,
                    title="Rate Limit Bypass via User-Agent Variation",
                    description=f"Rate limiting can be bypassed by changing the User-Agent header",
                    endpoint=endpoint,
                    method=method,
                    evidence=evidence,
                    remediation="Implement rate limiting based on more robust identifiers than User-Agent",
                    cwe_id="CWE-770",
                    owasp_category="API4:2023 Unrestricted Resource Consumption"
                )
                results.append(vulnerability)
                break  # Only report once for User-Agent bypass

            await asyncio.sleep(1)

        return results

    async def _test_request_variation_bypass(self, endpoint: str, method: str,
                                             params: Dict[str, Any] = None,
                                             headers: Dict[str, str] = None,
                                             data: Dict[str, Any] = None,
                                             baseline: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test rate limit bypass using request variations"""
        results = []

        for variation in self.request_variations:
            technique = variation['technique']

            if technique == 'case_variation':
                # Test different URL case variations
                varied_endpoints = [
                    endpoint.upper(),
                    endpoint.lower(),
                    endpoint.title()
                ]

                for varied_endpoint in varied_endpoints:
                    if varied_endpoint != endpoint:
                        bypass_successful = await self._test_rapid_requests(
                            varied_endpoint, method, params, headers, data, baseline
                        )

                        if bypass_successful:
                            evidence = {
                                'bypass_technique': 'case_variation',
                                'original_endpoint': endpoint,
                                'varied_endpoint': varied_endpoint,
                                'baseline_limit': baseline['requests_before_limit']
                            }

                            vulnerability = self.create_result(
                                vuln_type="Rate Limit Bypass",
                                severity=Severity.LOW,
                                title="Rate Limit Bypass via URL Case Variation",
                                description=f"Rate limiting bypassed using case variation: {varied_endpoint}",
                                endpoint=endpoint,
                                method=method,
                                evidence=evidence,
                                remediation="Normalize URLs before applying rate limiting",
                                cwe_id="CWE-770",
                                owasp_category="API4:2023 Unrestricted Resource Consumption"
                            )
                            results.append(vulnerability)

            elif technique == 'slash_variation':
                # Test trailing slash variation
                if endpoint.endswith('/'):
                    varied_endpoint = endpoint.rstrip('/')
                else:
                    varied_endpoint = endpoint + '/'

                bypass_successful = await self._test_rapid_requests(
                    varied_endpoint, method, params, headers, data, baseline
                )

                if bypass_successful:
                    evidence = {
                        'bypass_technique': 'slash_variation',
                        'original_endpoint': endpoint,
                        'varied_endpoint': varied_endpoint,
                        'baseline_limit': baseline['requests_before_limit']
                    }

                    vulnerability = self.create_result(
                        vuln_type="Rate Limit Bypass",
                        severity=Severity.LOW,
                        title="Rate Limit Bypass via Trailing Slash Variation",
                        description=f"Rate limiting bypassed using trailing slash variation",
                        endpoint=endpoint,
                        method=method,
                        evidence=evidence,
                        remediation="Normalize URLs (including trailing slashes) before applying rate limiting",
                        cwe_id="CWE-770",
                        owasp_category="API4:2023 Unrestricted Resource Consumption"
                    )
                    results.append(vulnerability)

            await asyncio.sleep(1)

        return results

    async def _test_rapid_requests(self, endpoint: str, method: str,
                                   params: Dict[str, Any] = None,
                                   headers: Dict[str, str] = None,
                                   data: Dict[str, Any] = None,
                                   baseline: Dict[str, Any] = None) -> bool:
        """Test if rapid requests can bypass rate limiting"""

        successful_requests = 0
        rate_limited = False

        # Send requests rapidly
        for i in range(self.rapid_request_count * 2):  # More than baseline limit
            response = await self.make_request(endpoint, method, params, headers, data)

            if not response:
                break

            if response.status in [429, 503]:
                rate_limited = True
                break
            elif response.status == 200:
                successful_requests += 1

            # Very short delay to test rapid requests
            await asyncio.sleep(0.05)

        # If we made more successful requests than the baseline limit without being rate limited,
        # then the bypass was successful
        if successful_requests > baseline['requests_before_limit'] and not rate_limited:
            return True

        return False

    async def _detect_rate_limit_response(self, response: aiohttp.ClientResponse) -> bool:
        """Detect if a response indicates rate limiting"""
        # Status code indicators
        if response.status in [429, 503]:
            return True

        # Header indicators
        rate_limit_headers = [
            'x-ratelimit-remaining', 'x-rate-limit-remaining',
            'ratelimit-remaining', 'rate-limit-remaining',
            'retry-after', 'x-retry-after'
        ]

        for header in rate_limit_headers:
            if header in response.headers:
                return True

        # Response body indicators
        response_text = getattr(response, '_text', '')
        if response_text:
            rate_limit_indicators = [
                'rate limit', 'too many requests', 'quota exceeded',
                'api limit', 'request limit', 'throttle'
            ]

            for indicator in rate_limit_indicators:
                if indicator in response_text.lower():
                    return True

        return False
