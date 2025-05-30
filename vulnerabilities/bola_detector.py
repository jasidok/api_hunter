"""
BOLA (Broken Object Level Authorization) / IDOR Detector

Detects vulnerabilities where users can access objects they shouldn't have access to
by manipulating object identifiers in API requests.
"""

import re
import json
import uuid
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
import aiohttp

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity


class BOLADetector(BaseVulnerabilityDetector):
    """
    Detector for Broken Object Level Authorization (BOLA) vulnerabilities
    
    BOLA occurs when an API endpoint allows users to access resources they
    shouldn't have permission to access by manipulating object identifiers.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        super().__init__(session, config)

        # Common ID patterns to look for in URLs and parameters
        self.id_patterns = [
            r'\b\d+\b',  # Numeric IDs
            r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b',  # UUIDs
            r'\b[a-f0-9]{24}\b',  # MongoDB ObjectIds
            r'\b[a-zA-Z0-9]{8,}\b',  # Generic alphanumeric IDs
        ]

        # Common parameter names that might contain object IDs
        self.id_parameter_names = [
            'id', 'user_id', 'userId', 'account_id', 'accountId',
            'order_id', 'orderId', 'transaction_id', 'transactionId',
            'file_id', 'fileId', 'document_id', 'documentId',
            'message_id', 'messageId', 'conversation_id', 'conversationId',
            'resource_id', 'resourceId', 'object_id', 'objectId',
            'item_id', 'itemId', 'product_id', 'productId',
            'profile_id', 'profileId', 'group_id', 'groupId'
        ]

        # Test values to try when manipulating IDs
        self.test_values = {
            'numeric': [1, 2, 100, 999, 9999, 0, -1],
            'uuid': [
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
                str(uuid.uuid4()),
                str(uuid.uuid4()),
            ],
            'mongodb': [
                '000000000000000000000000',
                '111111111111111111111111',
                'aaaaaaaaaaaaaaaaaaaaaaaa',
            ],
            'alphanumeric': ['admin', 'test', 'user1', 'abc123', '123abc', 'AAAA']
        }

    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect BOLA vulnerabilities in the given endpoint
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of BOLA vulnerabilities found
        """
        results = []

        # Test URL path parameters
        results.extend(await self._test_url_path_ids(endpoint, method, headers))

        # Test query parameters
        if params:
            results.extend(await self._test_query_params(endpoint, method, params, headers))

        # Test JSON body parameters
        if data and method in ['POST', 'PUT', 'PATCH']:
            results.extend(await self._test_body_params(endpoint, method, data, headers))

        return results

    async def _test_url_path_ids(self, endpoint: str, method: str,
                                 headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for BOLA in URL path segments"""
        results = []

        # Extract potential IDs from URL path
        url_parts = endpoint.split('/')
        id_positions = []

        for i, part in enumerate(url_parts):
            for pattern in self.id_patterns:
                if re.match(pattern, part):
                    id_positions.append((i, part, self._detect_id_type(part)))
                    break

        if not id_positions:
            return results

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')
        baseline_status = baseline_response.status

        # Test each ID position
        for pos, original_id, id_type in id_positions:
            for test_value in self.test_values.get(id_type, []):
                if str(test_value) == original_id:
                    continue

                # Create modified URL
                modified_parts = url_parts.copy()
                modified_parts[pos] = str(test_value)
                modified_url = '/'.join(modified_parts)

                # Make request with modified ID
                test_response = await self.make_request(modified_url, method, headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                # Analyze response for BOLA indicators
                vulnerability = await self._analyze_bola_response(
                    original_url=endpoint,
                    modified_url=modified_url,
                    original_id=original_id,
                    test_id=str(test_value),
                    baseline_response=baseline_response,
                    baseline_text=baseline_text,
                    test_response=test_response,
                    test_text=test_text,
                    method=method
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _test_query_params(self, endpoint: str, method: str,
                                 params: Dict[str, Any],
                                 headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for BOLA in query parameters"""
        results = []

        # Find ID-like parameters
        id_params = {}
        for param_name, param_value in params.items():
            if any(id_name in param_name.lower() for id_name in self.id_parameter_names):
                id_type = self._detect_id_type(str(param_value))
                if id_type:
                    id_params[param_name] = (param_value, id_type)

        if not id_params:
            return results

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, params=params, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test each ID parameter
        for param_name, (original_value, id_type) in id_params.items():
            for test_value in self.test_values.get(id_type, []):
                if str(test_value) == str(original_value):
                    continue

                # Create modified parameters
                modified_params = params.copy()
                modified_params[param_name] = test_value

                # Make request with modified parameter
                test_response = await self.make_request(endpoint, method, params=modified_params, headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                # Analyze response for BOLA indicators
                vulnerability = await self._analyze_bola_response(
                    original_url=endpoint,
                    modified_url=endpoint,
                    original_id=str(original_value),
                    test_id=str(test_value),
                    baseline_response=baseline_response,
                    baseline_text=baseline_text,
                    test_response=test_response,
                    test_text=test_text,
                    method=method,
                    param_name=param_name
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _test_body_params(self, endpoint: str, method: str,
                                data: Dict[str, Any],
                                headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for BOLA in request body parameters"""
        results = []

        # Find ID-like parameters in JSON body
        id_params = {}

        def find_id_params(obj, prefix=''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    if any(id_name in key.lower() for id_name in self.id_parameter_names):
                        id_type = self._detect_id_type(str(value))
                        if id_type:
                            id_params[full_key] = (value, id_type, key)
                    elif isinstance(value, (dict, list)):
                        find_id_params(value, full_key)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    find_id_params(item, f"{prefix}[{i}]")

        find_id_params(data)

        if not id_params:
            return results

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test each ID parameter
        for param_path, (original_value, id_type, param_name) in id_params.items():
            for test_value in self.test_values.get(id_type, []):
                if str(test_value) == str(original_value):
                    continue

                # Create modified data
                modified_data = json.loads(json.dumps(data))  # Deep copy

                # Set the modified value (simplified for top-level keys)
                if '.' not in param_path and '[' not in param_path:
                    modified_data[param_name] = test_value

                # Make request with modified data
                test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                # Analyze response for BOLA indicators
                vulnerability = await self._analyze_bola_response(
                    original_url=endpoint,
                    modified_url=endpoint,
                    original_id=str(original_value),
                    test_id=str(test_value),
                    baseline_response=baseline_response,
                    baseline_text=baseline_text,
                    test_response=test_response,
                    test_text=test_text,
                    method=method,
                    param_name=param_name
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _analyze_bola_response(self, original_url: str, modified_url: str,
                                     original_id: str, test_id: str,
                                     baseline_response: aiohttp.ClientResponse,
                                     baseline_text: str,
                                     test_response: aiohttp.ClientResponse,
                                     test_text: str,
                                     method: str,
                                     param_name: str = None) -> Optional[VulnerabilityResult]:
        """Analyze responses to detect BOLA vulnerability"""

        # Skip if test request failed
        if test_response.status >= 500:
            return None

        # BOLA indicators
        vulnerability_indicators = []
        severity = Severity.LOW

        # 1. Successful response with different content (potential unauthorized access)
        if (test_response.status == 200 and baseline_response.status == 200 and
                test_text != baseline_text and len(test_text) > 100):
            vulnerability_indicators.append("Different valid response for different ID")
            severity = Severity.HIGH

        # 2. Response contains data that looks like it belongs to another user/object
        if test_response.status == 200:
            # Look for user indicators in response that don't match the test ID
            user_patterns = [
                r'"user[_-]?id":\s*["\']?([^"\',\s}]+)',
                r'"username":\s*"([^"]+)"',
                r'"email":\s*"([^"]+)"',
                r'"name":\s*"([^"]+)"',
            ]

            for pattern in user_patterns:
                matches = re.findall(pattern, test_text, re.IGNORECASE)
                if matches and str(test_id) not in str(matches):
                    vulnerability_indicators.append(f"Response contains user data: {matches[:3]}")
                    severity = Severity.HIGH
                    break

        # 3. Status code indicates successful access when it shouldn't
        if baseline_response.status == 200 and test_response.status == 200:
            # If we're accessing a different ID and getting success, it might be BOLA
            if original_id != test_id:
                vulnerability_indicators.append("Successful access to different object ID")
                severity = Severity.MEDIUM

        # 4. Error messages revealing information about other objects
        error_patterns = [
            r'user.*not found',
            r'invalid.*user',
            r'access.*denied',
            r'unauthorized',
            r'forbidden'
        ]

        for pattern in error_patterns:
            if re.search(pattern, test_text, re.IGNORECASE):
                if test_response.status not in [401, 403]:
                    vulnerability_indicators.append(f"Information disclosure in error: {pattern}")
                    severity = Severity.MEDIUM

        if not vulnerability_indicators:
            return None

        # Create evidence
        evidence = {
            'original_id': original_id,
            'test_id': test_id,
            'original_url': original_url,
            'modified_url': modified_url,
            'baseline_status': baseline_response.status,
            'test_status': test_response.status,
            'baseline_content_length': len(baseline_text),
            'test_content_length': len(test_text),
            'indicators': vulnerability_indicators,
            'response_sample': test_text[:500] if test_text else '',
        }

        if param_name:
            evidence['parameter_name'] = param_name

        # Determine title and description
        param_info = f" in parameter '{param_name}'" if param_name else " in URL path"
        title = f"BOLA/IDOR Vulnerability{param_info}"

        description = (
            f"The endpoint allows unauthorized access to objects by manipulating "
            f"the ID parameter from '{original_id}' to '{test_id}'. "
            f"Indicators: {', '.join(vulnerability_indicators)}"
        )

        remediation = (
            "Implement proper authorization checks to ensure users can only access "
            "objects they own or have explicit permission to access. Validate that "
            "the authenticated user has permission to access the requested object ID."
        )

        return self.create_result(
            vuln_type="BOLA/IDOR",
            severity=severity,
            title=title,
            description=description,
            endpoint=original_url,
            method=method,
            evidence=evidence,
            remediation=remediation,
            cwe_id="CWE-639",
            owasp_category="API1:2023 Broken Object Level Authorization"
        )

    def _detect_id_type(self, value: str) -> Optional[str]:
        """Detect the type of ID based on its format"""
        if re.match(r'^\d+$', value):
            return 'numeric'
        elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', value, re.IGNORECASE):
            return 'uuid'
        elif re.match(r'^[a-f0-9]{24}$', value, re.IGNORECASE):
            return 'mongodb'
        elif re.match(r'^[a-zA-Z0-9]{8,}$', value):
            return 'alphanumeric'
        return None
