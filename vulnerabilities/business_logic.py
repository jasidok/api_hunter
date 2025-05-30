"""
Business Logic Vulnerability Detector

Detects logical flaws in API implementations that may not be obvious security
vulnerabilities but can lead to business logic bypasses and unauthorized operations.
"""

import re
import json
import copy
from typing import List, Dict, Any, Optional, Set
import aiohttp

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity


class BusinessLogicDetector(BaseVulnerabilityDetector):
    """
    Detector for Business Logic vulnerabilities
    
    Business logic flaws occur when the application's functionality can be used
    in ways that were not intended by the developers, potentially leading to
    unauthorized access or manipulation of data.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        super().__init__(session, config)

        # Price/amount manipulation test values
        self.price_values = [
            0, -1, -100, 0.01, -0.01, 999999, -999999,
            "0", "-1", "-100", "free", "null", "", "undefined"
        ]

        # Quantity manipulation test values
        self.quantity_values = [
            0, -1, -100, 999999, -999999,
            "0", "-1", "-100", "unlimited", "null", "", "undefined"
        ]

        # Common business logic parameters
        self.business_params = {
            'price': self.price_values,
            'cost': self.price_values,
            'amount': self.price_values,
            'total': self.price_values,
            'fee': self.price_values,
            'discount': self.price_values,
            'quantity': self.quantity_values,
            'qty': self.quantity_values,
            'count': self.quantity_values,
            'limit': self.quantity_values,
            'max': self.quantity_values,
            'min': self.quantity_values,
        }

        # Workflow bypass attempts
        self.workflow_bypass_params = {
            'status': ['approved', 'completed', 'verified', 'confirmed', 'paid', 'shipped'],
            'state': ['active', 'enabled', 'approved', 'verified'],
            'step': [999, 'final', 'complete', 'skip'],
            'stage': [999, 'final', 'complete', 'skip'],
            'phase': [999, 'final', 'complete', 'skip'],
        }

        # Time-based manipulation
        self.time_manipulation_params = {
            'date': ['1900-01-01', '2099-12-31', '0000-00-00'],
            'time': ['00:00:00', '23:59:59', '25:00:00'],
            'timestamp': [0, -1, 9999999999, '0', '-1'],
            'created_at': ['1900-01-01T00:00:00Z', '2099-12-31T23:59:59Z'],
            'updated_at': ['1900-01-01T00:00:00Z', '2099-12-31T23:59:59Z'],
            'expires_at': ['1900-01-01T00:00:00Z', '2099-12-31T23:59:59Z'],
        }

    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect business logic vulnerabilities in the given endpoint
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of business logic vulnerabilities found
        """
        results = []

        # Only test endpoints that modify data
        if method not in ['POST', 'PUT', 'PATCH']:
            return results

        # Test price/amount manipulation
        if data:
            results.extend(await self._test_price_manipulation(endpoint, method, data, headers))

            # Test workflow bypass
            results.extend(await self._test_workflow_bypass(endpoint, method, data, headers))

            # Test time manipulation
            results.extend(await self._test_time_manipulation(endpoint, method, data, headers))

            # Test quantity manipulation
            results.extend(await self._test_quantity_manipulation(endpoint, method, data, headers))

            # Test negative values
            results.extend(await self._test_negative_values(endpoint, method, data, headers))

        return results

    async def _test_price_manipulation(self, endpoint: str, method: str,
                                       data: Dict[str, Any],
                                       headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for price/amount manipulation vulnerabilities"""
        results = []

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Find price-related fields
        for field_name, field_value in data.items():
            field_lower = field_name.lower()

            if any(price_param in field_lower for price_param in ['price', 'cost', 'amount', 'total', 'fee']):
                for test_value in self.price_values:
                    modified_data = copy.deepcopy(data)
                    modified_data[field_name] = test_value

                    test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                    await self.rate_limit_delay()

                    if not test_response:
                        continue

                    test_text = getattr(test_response, '_text', '')

                    vulnerability = await self._analyze_business_logic_response(
                        endpoint=endpoint,
                        method=method,
                        vulnerability_type='price_manipulation',
                        field_name=field_name,
                        original_value=field_value,
                        test_value=test_value,
                        baseline_response=baseline_response,
                        baseline_text=baseline_text,
                        test_response=test_response,
                        test_text=test_text
                    )

                    if vulnerability:
                        results.append(vulnerability)

        return results

    async def _test_quantity_manipulation(self, endpoint: str, method: str,
                                          data: Dict[str, Any],
                                          headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for quantity manipulation vulnerabilities"""
        results = []

        baseline_response = await self.make_request(endpoint, method, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Find quantity-related fields
        for field_name, field_value in data.items():
            field_lower = field_name.lower()

            if any(qty_param in field_lower for qty_param in ['quantity', 'qty', 'count', 'limit']):
                for test_value in self.quantity_values:
                    modified_data = copy.deepcopy(data)
                    modified_data[field_name] = test_value

                    test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                    await self.rate_limit_delay()

                    if not test_response:
                        continue

                    test_text = getattr(test_response, '_text', '')

                    vulnerability = await self._analyze_business_logic_response(
                        endpoint=endpoint,
                        method=method,
                        vulnerability_type='quantity_manipulation',
                        field_name=field_name,
                        original_value=field_value,
                        test_value=test_value,
                        baseline_response=baseline_response,
                        baseline_text=baseline_text,
                        test_response=test_response,
                        test_text=test_text
                    )

                    if vulnerability:
                        results.append(vulnerability)

        return results

    async def _test_workflow_bypass(self, endpoint: str, method: str,
                                    data: Dict[str, Any],
                                    headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for workflow bypass vulnerabilities"""
        results = []

        baseline_response = await self.make_request(endpoint, method, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test workflow bypass parameters
        for param_name, test_values in self.workflow_bypass_params.items():
            # Add new workflow parameters
            for test_value in test_values:
                modified_data = copy.deepcopy(data)
                modified_data[param_name] = test_value

                test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                vulnerability = await self._analyze_business_logic_response(
                    endpoint=endpoint,
                    method=method,
                    vulnerability_type='workflow_bypass',
                    field_name=param_name,
                    original_value=None,
                    test_value=test_value,
                    baseline_response=baseline_response,
                    baseline_text=baseline_text,
                    test_response=test_response,
                    test_text=test_text
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _test_time_manipulation(self, endpoint: str, method: str,
                                      data: Dict[str, Any],
                                      headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for time manipulation vulnerabilities"""
        results = []

        baseline_response = await self.make_request(endpoint, method, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test time manipulation parameters
        for param_name, test_values in self.time_manipulation_params.items():
            for test_value in test_values:
                modified_data = copy.deepcopy(data)
                modified_data[param_name] = test_value

                test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                vulnerability = await self._analyze_business_logic_response(
                    endpoint=endpoint,
                    method=method,
                    vulnerability_type='time_manipulation',
                    field_name=param_name,
                    original_value=data.get(param_name),
                    test_value=test_value,
                    baseline_response=baseline_response,
                    baseline_text=baseline_text,
                    test_response=test_response,
                    test_text=test_text
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _test_negative_values(self, endpoint: str, method: str,
                                    data: Dict[str, Any],
                                    headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for negative value manipulation"""
        results = []

        baseline_response = await self.make_request(endpoint, method, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test negative values on numeric fields
        for field_name, field_value in data.items():
            if isinstance(field_value, (int, float)) and field_value > 0:
                # Test negative version of positive numbers
                test_value = -abs(field_value)

                modified_data = copy.deepcopy(data)
                modified_data[field_name] = test_value

                test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                vulnerability = await self._analyze_business_logic_response(
                    endpoint=endpoint,
                    method=method,
                    vulnerability_type='negative_value',
                    field_name=field_name,
                    original_value=field_value,
                    test_value=test_value,
                    baseline_response=baseline_response,
                    baseline_text=baseline_text,
                    test_response=test_response,
                    test_text=test_text
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _analyze_business_logic_response(self, endpoint: str, method: str,
                                               vulnerability_type: str, field_name: str,
                                               original_value: Any, test_value: Any,
                                               baseline_response: aiohttp.ClientResponse,
                                               baseline_text: str,
                                               test_response: aiohttp.ClientResponse,
                                               test_text: str) -> Optional[VulnerabilityResult]:
        """Analyze response for business logic vulnerabilities"""

        # Skip if request failed with server error
        if test_response.status >= 500:
            return None

        vulnerability_indicators = []
        severity = Severity.LOW

        # 1. Check for successful operations with invalid values
        if test_response.status in [200, 201, 202]:
            if vulnerability_type == 'price_manipulation':
                if test_value in [0, -1, -100, "0", "-1", "-100"]:
                    vulnerability_indicators.append(f"Accepted invalid price value: {test_value}")
                    severity = Severity.HIGH

            elif vulnerability_type == 'quantity_manipulation':
                if test_value in [0, -1, -100, "0", "-1", "-100"]:
                    vulnerability_indicators.append(f"Accepted invalid quantity value: {test_value}")
                    severity = Severity.MEDIUM

            elif vulnerability_type == 'workflow_bypass':
                vulnerability_indicators.append(f"Workflow bypass successful with {field_name}={test_value}")
                severity = Severity.HIGH

            elif vulnerability_type == 'time_manipulation':
                vulnerability_indicators.append(f"Time manipulation accepted: {field_name}={test_value}")
                severity = Severity.MEDIUM

            elif vulnerability_type == 'negative_value':
                vulnerability_indicators.append(f"Negative value accepted: {field_name}={test_value}")
                severity = Severity.MEDIUM

        # 2. Check for business logic bypass indicators in response
        bypass_indicators = [
            r'total.*0',
            r'price.*0',
            r'cost.*0',
            r'amount.*0',
            r'free',
            r'complimentary',
            r'no.*charge',
            r'approved',
            r'verified',
            r'completed',
            r'success.*bypass'
        ]

        for indicator in bypass_indicators:
            if re.search(indicator, test_text, re.IGNORECASE):
                vulnerability_indicators.append(f"Business logic bypass indicator: {indicator}")
                if severity == Severity.LOW:
                    severity = Severity.MEDIUM

        # 3. Check for calculation errors
        if vulnerability_type in ['price_manipulation', 'quantity_manipulation']:
            if self._detect_calculation_errors(test_text, test_value):
                vulnerability_indicators.append("Calculation error detected in response")
                severity = Severity.HIGH

        # 4. Check for response content changes indicating successful manipulation
        if self._detect_significant_response_change(baseline_text, test_text):
            vulnerability_indicators.append("Significant response change indicating successful manipulation")
            if severity == Severity.LOW:
                severity = Severity.MEDIUM

        if not vulnerability_indicators:
            return None

        # Create evidence
        evidence = {
            'vulnerability_type': vulnerability_type,
            'field_name': field_name,
            'original_value': str(original_value) if original_value is not None else None,
            'test_value': str(test_value),
            'baseline_status': baseline_response.status,
            'test_status': test_response.status,
            'indicators': vulnerability_indicators,
            'response_sample': test_text[:500] if test_text else ''
        }

        # Create vulnerability result
        title_mapping = {
            'price_manipulation': f"Price Manipulation in {field_name}",
            'quantity_manipulation': f"Quantity Manipulation in {field_name}",
            'workflow_bypass': f"Workflow Bypass via {field_name}",
            'time_manipulation': f"Time Manipulation in {field_name}",
            'negative_value': f"Negative Value Bypass in {field_name}"
        }

        description_mapping = {
            'price_manipulation': f"Price manipulation vulnerability allowing invalid price values in {field_name}",
            'quantity_manipulation': f"Quantity manipulation vulnerability allowing invalid quantities in {field_name}",
            'workflow_bypass': f"Workflow bypass vulnerability allowing state manipulation via {field_name}",
            'time_manipulation': f"Time manipulation vulnerability allowing invalid dates/times in {field_name}",
            'negative_value': f"Negative value bypass allowing negative numbers in {field_name}"
        }

        remediation_mapping = {
            'price_manipulation': "Implement proper price validation with minimum/maximum limits and business rules",
            'quantity_manipulation': "Implement proper quantity validation with appropriate limits and constraints",
            'workflow_bypass': "Implement proper workflow validation and state management controls",
            'time_manipulation': "Implement proper date/time validation and constraints",
            'negative_value': "Implement proper input validation to prevent negative values where inappropriate"
        }

        return self.create_result(
            vuln_type="Business Logic Flaw",
            severity=severity,
            title=title_mapping.get(vulnerability_type, f"Business Logic Flaw in {field_name}"),
            description=description_mapping.get(vulnerability_type, f"Business logic vulnerability in {field_name}"),
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            remediation=remediation_mapping.get(vulnerability_type, "Implement proper business logic validation"),
            cwe_id="CWE-840",
            owasp_category="API7:2023 Server Side Request Forgery"
        )

    def _detect_calculation_errors(self, response_text: str, test_value: Any) -> bool:
        """Detect calculation errors in the response"""
        try:
            # Look for numerical values in response that might indicate calculation errors
            numbers = re.findall(r'-?\d+\.?\d*', response_text)

            # Check for suspicious calculations with our test value
            if str(test_value) in ["-1", "-100", "0"]:
                for num in numbers:
                    try:
                        if float(num) <= 0 and "total" in response_text.lower():
                            return True
                    except ValueError:
                        continue

        except Exception:
            pass

        return False

    def _detect_significant_response_change(self, baseline_text: str, test_text: str) -> bool:
        """Detect significant changes in response content"""
        if not baseline_text or not test_text:
            return False

        # Check for length changes
        length_diff = abs(len(test_text) - len(baseline_text))
        if length_diff > 100:
            return True

        # Check for new success indicators
        success_patterns = [
            r'success', r'approved', r'verified', r'completed',
            r'total.*0', r'free', r'complimentary'
        ]

        for pattern in success_patterns:
            baseline_matches = len(re.findall(pattern, baseline_text, re.IGNORECASE))
            test_matches = len(re.findall(pattern, test_text, re.IGNORECASE))
            if test_matches > baseline_matches:
                return True

        return False
