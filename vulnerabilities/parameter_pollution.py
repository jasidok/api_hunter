"""
Parameter Pollution Detector

Detects HTTP Parameter Pollution (HPP) vulnerabilities where APIs handle
duplicate parameters in unexpected ways, potentially leading to security issues.
"""

import re
import json
import copy
import urllib.parse
from typing import List, Dict, Any, Optional, Set
import aiohttp

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity


class ParameterPollutionDetector(BaseVulnerabilityDetector):
    """
    Detector for HTTP Parameter Pollution vulnerabilities
    
    HTTP Parameter Pollution occurs when an application accepts multiple parameters
    with the same name and processes them in unexpected ways, potentially leading
    to security bypasses or logical flaws.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        super().__init__(session, config)

        # Test values for parameter pollution
        self.pollution_values = [
            'admin', 'true', 'false', '1', '0', '-1',
            'null', 'undefined', '', 'test',
            '../', '../../', '/etc/passwd',
            '<script>', '\'or 1=1--', '${7*7}',
            'OR 1=1', 'AND 1=1', 'UNION SELECT'
        ]

        # Common parameter names to test for pollution
        self.test_parameters = [
            'id', 'user_id', 'admin', 'role', 'access',
            'action', 'method', 'type', 'status',
            'limit', 'page', 'count', 'format'
        ]

        # Different parameter pollution techniques
        self.pollution_techniques = [
            'duplicate_query',  # ?param=value1&param=value2
            'array_notation',  # ?param[]=value1&param[]=value2
            'mixed_formats',  # ?param=value1&param[]=value2
            'encoded_duplicates',  # ?param=value1&param%5B%5D=value2
        ]

    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect parameter pollution vulnerabilities in the given endpoint
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of parameter pollution vulnerabilities found
        """
        results = []

        # Test query parameter pollution
        if params:
            results.extend(await self._test_query_parameter_pollution(endpoint, method, params, headers, data))

        # Test JSON body parameter pollution (less common but possible)
        if data and method in ['POST', 'PUT', 'PATCH']:
            results.extend(await self._test_json_parameter_pollution(endpoint, method, data, headers))

        # Test form data parameter pollution
        results.extend(await self._test_form_parameter_pollution(endpoint, method, params, headers, data))

        return results

    async def _test_query_parameter_pollution(self, endpoint: str, method: str,
                                              params: Dict[str, Any],
                                              headers: Dict[str, str] = None,
                                              data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for parameter pollution in query parameters"""
        results = []

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, params=params, headers=headers, data=data)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test existing parameters for pollution
        for param_name, param_value in params.items():
            for pollution_value in self.pollution_values:
                if str(pollution_value) == str(param_value):
                    continue  # Skip if same as original value

                # Test different pollution techniques
                for technique in self.pollution_techniques:
                    vulnerability = await self._test_parameter_pollution_technique(
                        endpoint, method, param_name, param_value, pollution_value,
                        technique, 'query_param', params, headers, data,
                        baseline_response, baseline_text
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

        # Test injection of new parameters
        for param_name in self.test_parameters:
            if param_name not in params:
                for pollution_value in self.pollution_values[:5]:  # Limit to reduce requests
                    vulnerability = await self._test_parameter_pollution_technique(
                        endpoint, method, param_name, None, pollution_value,
                        'duplicate_query', 'query_param', params, headers, data,
                        baseline_response, baseline_text
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

        return results

    async def _test_json_parameter_pollution(self, endpoint: str, method: str,
                                             data: Dict[str, Any],
                                             headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for parameter pollution in JSON body"""
        results = []

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test existing JSON fields
        for field_name, field_value in data.items():
            # Try to create array pollution
            for pollution_value in self.pollution_values[:3]:  # Limit pollution values
                modified_data = copy.deepcopy(data)

                # Convert single value to array with pollution
                if not isinstance(field_value, list):
                    modified_data[field_name] = [field_value, pollution_value]
                else:
                    modified_data[field_name] = field_value + [pollution_value]

                test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                vulnerability = await self._analyze_pollution_response(
                    endpoint, method, field_name, field_value, pollution_value,
                    'json_array_pollution', 'json_body',
                    baseline_response, baseline_text, test_response, test_text
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _test_form_parameter_pollution(self, endpoint: str, method: str,
                                             params: Dict[str, Any] = None,
                                             headers: Dict[str, str] = None,
                                             data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for parameter pollution in form data"""
        results = []

        if method not in ['POST', 'PUT', 'PATCH']:
            return results

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, params=params, headers=headers, data=data)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test form data pollution by manually crafting requests
        for param_name in self.test_parameters:
            for pollution_value in self.pollution_values[:3]:
                # Create form data with duplicate parameters
                form_data = aiohttp.FormData()

                # Add existing data first
                if data:
                    for key, value in data.items():
                        form_data.add_field(key, str(value))

                # Add duplicate pollution parameter
                form_data.add_field(param_name, 'original')
                form_data.add_field(param_name, str(pollution_value))

                test_response = await self.make_request(endpoint, method, params=params, headers=headers,
                                                        data=form_data)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                vulnerability = await self._analyze_pollution_response(
                    endpoint, method, param_name, 'original', pollution_value,
                    'form_pollution', 'form_data',
                    baseline_response, baseline_text, test_response, test_text
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _test_parameter_pollution_technique(self, endpoint: str, method: str,
                                                  param_name: str, original_value: Any,
                                                  pollution_value: Any, technique: str,
                                                  location: str, base_params: Dict[str, Any],
                                                  headers: Dict[str, str] = None,
                                                  data: Dict[str, Any] = None,
                                                  baseline_response: aiohttp.ClientResponse = None,
                                                  baseline_text: str = '') -> Optional[VulnerabilityResult]:
        """Test a specific parameter pollution technique"""

        # Create the polluted URL manually based on technique
        polluted_url = self._create_polluted_url(endpoint, base_params, param_name, original_value, pollution_value,
                                                 technique)

        # Make request to polluted URL
        # Parse the URL to separate endpoint and query string
        parsed_url = urllib.parse.urlparse(polluted_url)
        clean_endpoint = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        # For this test, we'll make the request directly to the polluted URL
        test_response = await self._make_raw_request(polluted_url, method, headers, data)

        if not test_response:
            return None

        test_text = getattr(test_response, '_text', '')

        return await self._analyze_pollution_response(
            endpoint, method, param_name, original_value, pollution_value,
            technique, location, baseline_response, baseline_text, test_response, test_text
        )

    def _create_polluted_url(self, endpoint: str, base_params: Dict[str, Any],
                             param_name: str, original_value: Any, pollution_value: Any,
                             technique: str) -> str:
        """Create a URL with parameter pollution based on technique"""

        # Start with base URL and parameters
        if '?' in endpoint:
            base_url = endpoint
        else:
            query_parts = []
            for key, value in (base_params or {}).items():
                query_parts.append(f"{key}={urllib.parse.quote(str(value))}")

            if query_parts:
                base_url = f"{endpoint}?{'&'.join(query_parts)}"
            else:
                base_url = endpoint

        # Add pollution based on technique
        separator = '&' if '?' in base_url else '?'

        if technique == 'duplicate_query':
            # ?param=value1&param=value2
            if original_value is not None:
                pollution_part = f"{param_name}={urllib.parse.quote(str(pollution_value))}"
            else:
                pollution_part = f"{param_name}=original&{param_name}={urllib.parse.quote(str(pollution_value))}"

        elif technique == 'array_notation':
            # ?param[]=value1&param[]=value2
            if original_value is not None:
                pollution_part = f"{param_name}[]={urllib.parse.quote(str(pollution_value))}"
            else:
                pollution_part = f"{param_name}[]=original&{param_name}[]={urllib.parse.quote(str(pollution_value))}"

        elif technique == 'mixed_formats':
            # ?param=value1&param[]=value2
            pollution_part = f"{param_name}[]={urllib.parse.quote(str(pollution_value))}"

        elif technique == 'encoded_duplicates':
            # ?param=value1&param%5B%5D=value2 (URL encoded)
            encoded_param = urllib.parse.quote(f"{param_name}[]")
            pollution_part = f"{encoded_param}={urllib.parse.quote(str(pollution_value))}"

        else:
            pollution_part = f"{param_name}={urllib.parse.quote(str(pollution_value))}"

        return f"{base_url}{separator}{pollution_part}"

    async def _make_raw_request(self, url: str, method: str,
                                headers: Dict[str, str] = None,
                                data: Any = None) -> Optional[aiohttp.ClientResponse]:
        """Make a raw HTTP request to a URL"""
        try:
            headers = headers or {}
            if 'User-Agent' not in headers:
                headers['User-Agent'] = 'API-Hunter/1.0 (Security Scanner)'

            async with self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as response:
                response_text = await response.text()
                response._text = response_text
                return response

        except Exception:
            return None

    async def _analyze_pollution_response(self, endpoint: str, method: str,
                                          param_name: str, original_value: Any,
                                          pollution_value: Any, technique: str,
                                          location: str,
                                          baseline_response: aiohttp.ClientResponse,
                                          baseline_text: str,
                                          test_response: aiohttp.ClientResponse,
                                          test_text: str) -> Optional[VulnerabilityResult]:
        """Analyze response for parameter pollution indicators"""

        # Skip if request failed
        if test_response.status >= 500:
            return None

        vulnerability_indicators = []
        severity = Severity.LOW

        # 1. Check for different response content
        if test_text != baseline_text:
            # Check if pollution value appears in response
            if str(pollution_value) in test_text and str(pollution_value) not in baseline_text:
                vulnerability_indicators.append(f"Pollution value '{pollution_value}' reflected in response")
                severity = Severity.MEDIUM

        # 2. Check for different status codes
        if test_response.status != baseline_response.status:
            vulnerability_indicators.append(
                f"Status code changed from {baseline_response.status} to {test_response.status}")
            severity = Severity.MEDIUM

        # 3. Check for security bypass indicators
        security_bypass_patterns = [
            r'admin', r'administrator', r'root', r'superuser',
            r'true', r'success', r'granted', r'authorized'
        ]

        for pattern in security_bypass_patterns:
            if (re.search(pattern, test_text, re.IGNORECASE) and
                    not re.search(pattern, baseline_text, re.IGNORECASE)):
                vulnerability_indicators.append(f"Security bypass pattern detected: {pattern}")
                severity = Severity.HIGH
                break

        # 4. Check for error patterns indicating parameter processing
        error_patterns = [
            r'duplicate.*parameter',
            r'multiple.*values',
            r'array.*expected',
            r'invalid.*parameter.*format'
        ]

        for pattern in error_patterns:
            if re.search(pattern, test_text, re.IGNORECASE):
                vulnerability_indicators.append(f"Parameter processing error: {pattern}")
                severity = Severity.LOW

        # 5. Check for content length changes
        length_diff = abs(len(test_text) - len(baseline_text))
        if length_diff > 100:
            vulnerability_indicators.append(f"Significant content length change: {length_diff} bytes")
            if severity == Severity.LOW:
                severity = Severity.MEDIUM

        # 6. Check for injection patterns being processed
        injection_patterns = [
            r'<script.*?>.*?</script>',
            r'alert\(',
            r'document\.',
            r'SELECT.*FROM',
            r'UNION.*SELECT'
        ]

        for pattern in injection_patterns:
            if (re.search(pattern, test_text, re.IGNORECASE) and
                    not re.search(pattern, baseline_text, re.IGNORECASE)):
                vulnerability_indicators.append(f"Injection pattern detected: {pattern}")
                severity = Severity.HIGH
                break

        if not vulnerability_indicators:
            return None

        # Create evidence
        evidence = {
            'parameter_name': param_name,
            'original_value': str(original_value) if original_value is not None else None,
            'pollution_value': str(pollution_value),
            'technique': technique,
            'location': location,
            'baseline_status': baseline_response.status,
            'test_status': test_response.status,
            'baseline_content_length': len(baseline_text),
            'test_content_length': len(test_text),
            'indicators': vulnerability_indicators,
            'response_sample': test_text[:500] if test_text else ''
        }

        title = f"Parameter Pollution in {param_name} ({technique})"
        description = (
            f"HTTP Parameter Pollution vulnerability detected in parameter '{param_name}' "
            f"using technique '{technique}'. The application processes duplicate parameters "
            f"in an unexpected way. Pollution value: '{pollution_value}'. "
            f"Indicators: {', '.join(vulnerability_indicators)}"
        )

        remediation = (
            "Implement proper parameter handling to reject or normalize duplicate parameters. "
            "Use explicit parameter parsing that handles only the first occurrence of each parameter. "
            "Validate and sanitize all parameter values regardless of their position."
        )

        return self.create_result(
            vuln_type="Parameter Pollution",
            severity=severity,
            title=title,
            description=description,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            remediation=remediation,
            cwe_id="CWE-235",
            owasp_category="API8:2023 Security Misconfiguration"
        )
