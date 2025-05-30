"""
Mass Assignment Vulnerability Detector

Detects vulnerabilities where APIs automatically bind request parameters to object properties
without proper filtering, allowing attackers to modify unintended fields.
"""

import re
import json
import copy
from typing import List, Dict, Any, Optional, Set
import aiohttp

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity


class MassAssignmentDetector(BaseVulnerabilityDetector):
    """
    Detector for Mass Assignment vulnerabilities
    
    Mass Assignment occurs when an application automatically binds HTTP request parameters
    to program variables or object properties without proper filtering, allowing attackers
    to modify fields they shouldn't have access to.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        super().__init__(session, config)

        # Common sensitive fields that should not be mass-assignable
        self.sensitive_fields = [
            # User/Account fields
            'id', 'user_id', 'userId', 'account_id', 'accountId',
            'role', 'roles', 'user_role', 'userRole',
            'admin', 'is_admin', 'isAdmin', 'administrator',
            'privilege', 'privileges', 'permission', 'permissions',
            'access_level', 'accessLevel', 'level',
            'active', 'is_active', 'isActive', 'enabled',
            'verified', 'is_verified', 'isVerified',
            'confirmed', 'is_confirmed', 'isConfirmed',
            'status', 'user_status', 'userStatus', 'account_status',

            # Financial fields
            'balance', 'credit', 'price', 'cost', 'amount',
            'paid', 'payment_status', 'paymentStatus',
            'discount', 'fee', 'commission',

            # System fields
            'created_at', 'createdAt', 'updated_at', 'updatedAt',
            'created_by', 'createdBy', 'updated_by', 'updatedBy',
            'deleted_at', 'deletedAt', 'deleted',
            'version', 'revision', 'hash',

            # Security fields
            'password', 'password_hash', 'passwordHash',
            'salt', 'token', 'api_key', 'apiKey',
            'secret', 'secret_key', 'secretKey',
            'csrf_token', 'csrfToken',

            # System configuration
            'config', 'configuration', 'settings',
            'flags', 'options', 'metadata'
        ]

        # Common field name patterns to test
        self.test_field_patterns = [
            # Boolean flags
            {'pattern': r'is_(\w+)', 'values': [True, False, 1, 0, 'true', 'false']},
            {'pattern': r'has_(\w+)', 'values': [True, False, 1, 0, 'true', 'false']},
            {'pattern': r'can_(\w+)', 'values': [True, False, 1, 0, 'true', 'false']},

            # Status fields
            {'pattern': r'(\w+)_status', 'values': ['active', 'inactive', 'pending', 'approved', 'admin']},
            {'pattern': r'status', 'values': ['active', 'inactive', 'pending', 'approved', 'admin']},

            # Level/Role fields
            {'pattern': r'(\w+)_level', 'values': ['admin', 'high', 'max', '999', '100']},
            {'pattern': r'level', 'values': ['admin', 'high', 'max', '999', '100']},
            {'pattern': r'role', 'values': ['admin', 'administrator', 'root', 'superuser']},

            # ID fields
            {'pattern': r'(\w+)_id', 'values': [1, 999, 0, -1, 'admin']},
        ]

    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect Mass Assignment vulnerabilities in the given endpoint
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of Mass Assignment vulnerabilities found
        """
        results = []

        # Only test endpoints that accept data modification
        if method not in ['POST', 'PUT', 'PATCH']:
            return results

        # Test sensitive field injection in request body
        if data:
            results.extend(await self._test_json_mass_assignment(endpoint, method, data, headers))

        # Test query parameter mass assignment
        results.extend(await self._test_query_param_mass_assignment(endpoint, method, params, headers, data))

        return results

    async def _test_json_mass_assignment(self, endpoint: str, method: str,
                                         data: Dict[str, Any],
                                         headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test for mass assignment in JSON request body"""
        results = []

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')

        # Test injecting sensitive fields
        for field_name in self.sensitive_fields:
            if field_name in data:
                continue  # Skip if field already exists

            test_values = self._get_test_values_for_field(field_name)

            for test_value in test_values:
                # Create modified data with injected field
                modified_data = copy.deepcopy(data)
                modified_data[field_name] = test_value

                test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                # Analyze response for mass assignment indicators
                vulnerability = await self._analyze_mass_assignment_response(
                    endpoint=endpoint,
                    method=method,
                    field_name=field_name,
                    test_value=test_value,
                    location='request_body',
                    baseline_response=baseline_response,
                    baseline_text=baseline_text,
                    test_response=test_response,
                    test_text=test_text
                )

                if vulnerability:
                    results.append(vulnerability)

        # Test pattern-based field injection
        for pattern_info in self.test_field_patterns:
            pattern = pattern_info['pattern']
            values = pattern_info['values']

            # Generate field names based on context
            test_fields = self._generate_contextual_fields(data, pattern)

            for field_name in test_fields:
                if field_name in data:
                    continue

                for test_value in values:
                    modified_data = copy.deepcopy(data)
                    modified_data[field_name] = test_value

                    test_response = await self.make_request(endpoint, method, data=modified_data, headers=headers)
                    await self.rate_limit_delay()

                    if not test_response:
                        continue

                    test_text = getattr(test_response, '_text', '')

                    vulnerability = await self._analyze_mass_assignment_response(
                        endpoint=endpoint,
                        method=method,
                        field_name=field_name,
                        test_value=test_value,
                        location='request_body',
                        baseline_response=baseline_response,
                        baseline_text=baseline_text,
                        test_response=test_response,
                        test_text=test_text
                    )

                    if vulnerability:
                        results.append(vulnerability)

        return results

    async def _test_query_param_mass_assignment(self, endpoint: str, method: str,
                                                params: Dict[str, Any] = None,
                                                headers: Dict[str, str] = None,
                                                data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for mass assignment through query parameters"""
        results = []

        # Get baseline response
        baseline_response = await self.make_request(endpoint, method, params=params, data=data, headers=headers)
        if not baseline_response:
            return results

        baseline_text = getattr(baseline_response, '_text', '')
        base_params = params or {}

        # Test injecting sensitive fields as query parameters
        for field_name in self.sensitive_fields[:10]:  # Limit to avoid too many requests
            if field_name in base_params:
                continue

            test_values = self._get_test_values_for_field(field_name)

            for test_value in test_values[:2]:  # Limit test values
                # Create modified parameters
                modified_params = base_params.copy()
                modified_params[field_name] = test_value

                test_response = await self.make_request(endpoint, method, params=modified_params, data=data,
                                                        headers=headers)
                await self.rate_limit_delay()

                if not test_response:
                    continue

                test_text = getattr(test_response, '_text', '')

                vulnerability = await self._analyze_mass_assignment_response(
                    endpoint=endpoint,
                    method=method,
                    field_name=field_name,
                    test_value=test_value,
                    location='query_params',
                    baseline_response=baseline_response,
                    baseline_text=baseline_text,
                    test_response=test_response,
                    test_text=test_text
                )

                if vulnerability:
                    results.append(vulnerability)

        return results

    async def _analyze_mass_assignment_response(self, endpoint: str, method: str,
                                                field_name: str, test_value: Any,
                                                location: str,
                                                baseline_response: aiohttp.ClientResponse,
                                                baseline_text: str,
                                                test_response: aiohttp.ClientResponse,
                                                test_text: str) -> Optional[VulnerabilityResult]:
        """Analyze response to detect mass assignment vulnerability"""

        # Skip if request failed
        if test_response.status >= 500:
            return None

        vulnerability_indicators = []
        severity = Severity.LOW

        # 1. Check if injected field appears in response
        field_in_response = self._check_field_in_response(field_name, test_value, test_text)
        if field_in_response:
            vulnerability_indicators.append(f"Injected field '{field_name}' reflected in response")
            severity = Severity.MEDIUM

        # 2. Check for privilege escalation indicators
        if self._check_privilege_escalation(field_name, test_value, test_text):
            vulnerability_indicators.append("Potential privilege escalation detected")
            severity = Severity.HIGH

        # 3. Check for successful creation/update with injected field
        if (test_response.status in [200, 201, 202] and
                baseline_response.status in [200, 201, 202] and
                self._indicates_successful_operation(test_text)):
            vulnerability_indicators.append("Operation succeeded with injected field")
            if severity == Severity.LOW:
                severity = Severity.MEDIUM

        # 4. Check for behavior changes
        if self._detect_behavior_change(baseline_text, test_text):
            vulnerability_indicators.append("Response behavior changed with injected field")
            if severity == Severity.LOW:
                severity = Severity.MEDIUM

        # 5. Check for sensitive field acceptance
        if field_name in self.sensitive_fields and test_response.status in [200, 201, 202]:
            vulnerability_indicators.append(f"Sensitive field '{field_name}' was accepted")
            severity = Severity.MEDIUM

        if not vulnerability_indicators:
            return None

        # Create evidence
        evidence = {
            'injected_field': field_name,
            'test_value': str(test_value),
            'location': location,
            'baseline_status': baseline_response.status,
            'test_status': test_response.status,
            'indicators': vulnerability_indicators,
            'response_sample': test_text[:500] if test_text else '',
            'field_in_response': field_in_response
        }

        title = f"Mass Assignment - {field_name} field injection"
        description = (
            f"The API accepts and potentially processes the injected field '{field_name}' "
            f"with value '{test_value}' in {location}. "
            f"Indicators: {', '.join(vulnerability_indicators)}"
        )

        remediation = (
            "Implement proper input validation and use explicit allow-lists for acceptable fields. "
            "Avoid automatic binding of all request parameters to object properties. "
            "Use Data Transfer Objects (DTOs) or explicit field mapping to control which fields can be modified."
        )

        return self.create_result(
            vuln_type="Mass Assignment",
            severity=severity,
            title=title,
            description=description,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            remediation=remediation,
            cwe_id="CWE-915",
            owasp_category="API6:2023 Unrestricted Resource Consumption"
        )

    def _get_test_values_for_field(self, field_name: str) -> List[Any]:
        """Get appropriate test values for a field based on its name"""
        field_lower = field_name.lower()

        # Boolean-like fields
        if any(keyword in field_lower for keyword in ['is_', 'has_', 'can_', 'admin', 'active', 'enabled', 'verified']):
            return [True, False, 1, 0, 'true', 'false', 'yes', 'no']

        # Role/privilege fields
        if any(keyword in field_lower for keyword in ['role', 'privilege', 'permission', 'level']):
            return ['admin', 'administrator', 'root', 'superuser', 'high', 'max']

        # Status fields
        if 'status' in field_lower:
            return ['active', 'admin', 'approved', 'verified', 'confirmed']

        # ID fields
        if field_lower.endswith('_id') or field_lower == 'id':
            return [1, 999, 0, -1, 'admin']

        # Numeric fields
        if any(keyword in field_lower for keyword in ['balance', 'amount', 'price', 'cost', 'discount']):
            return [0, 999999, -1000, 1000000]

        # Default values
        return [True, 'admin', 1, 'test']

    def _generate_contextual_fields(self, data: Dict[str, Any], pattern: str) -> List[str]:
        """Generate field names based on existing data context and patterns"""
        fields = []

        # Extract words from existing field names
        existing_words = set()
        for key in data.keys():
            # Split camelCase and snake_case
            words = re.findall(r'[A-Z][a-z]*|[a-z]+', key)
            existing_words.update(word.lower() for word in words)

        # Generate fields based on pattern and context
        if 'is_' in pattern:
            for word in existing_words:
                fields.append(f'is_{word}')
            fields.extend(['is_admin', 'is_active', 'is_verified', 'is_enabled'])

        elif 'status' in pattern:
            for word in existing_words:
                fields.append(f'{word}_status')
            fields.extend(['status', 'user_status', 'account_status'])

        elif 'level' in pattern:
            for word in existing_words:
                fields.append(f'{word}_level')
            fields.extend(['level', 'access_level', 'privilege_level'])

        elif 'role' in pattern:
            fields.extend(['role', 'user_role', 'roles'])

        elif '_id' in pattern:
            for word in existing_words:
                fields.append(f'{word}_id')

        return fields[:5]  # Limit to avoid too many requests

    def _check_field_in_response(self, field_name: str, test_value: Any, response_text: str) -> bool:
        """Check if the injected field appears in the response"""
        try:
            # Try to parse as JSON first
            response_data = json.loads(response_text)

            # Check for field in JSON response
            def check_nested(obj, field, value):
                if isinstance(obj, dict):
                    if field in obj and str(obj[field]) == str(value):
                        return True
                    for v in obj.values():
                        if check_nested(v, field, value):
                            return True
                elif isinstance(obj, list):
                    for item in obj:
                        if check_nested(item, field, value):
                            return True
                return False

            return check_nested(response_data, field_name, test_value)

        except (json.JSONDecodeError, TypeError):
            # Fall back to text search
            field_patterns = [
                f'"{field_name}"\\s*:\\s*"{test_value}"',
                f'"{field_name}"\\s*:\\s*{test_value}',
                f'{field_name}.*{test_value}',
            ]

            for pattern in field_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True

        return False

    def _check_privilege_escalation(self, field_name: str, test_value: Any, response_text: str) -> bool:
        """Check if the mass assignment led to privilege escalation"""
        privilege_indicators = [
            r'"role"\\s*:\\s*"admin"',
            r'"is_admin"\\s*:\\s*true',
            r'"admin"\\s*:\\s*true',
            r'"privilege"\\s*:\\s*"admin"',
            r'"access_level"\\s*:\\s*"admin"',
            r'administrator',
            r'elevated.*privilege'
        ]

        for indicator in privilege_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True

        return False

    def _indicates_successful_operation(self, response_text: str) -> bool:
        """Check if response indicates a successful operation"""
        success_patterns = [
            r'"success"\\s*:\\s*true',
            r'"status"\\s*:\\s*"success"',
            r'"created"\\s*:\\s*true',
            r'"updated"\\s*:\\s*true',
            r'successfully',
            r'created',
            r'updated'
        ]

        for pattern in success_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _detect_behavior_change(self, baseline_text: str, test_text: str) -> bool:
        """Detect significant behavior changes between baseline and test responses"""
        if not baseline_text or not test_text:
            return False

        # Check for significant content length difference
        length_diff = abs(len(test_text) - len(baseline_text))
        if length_diff > 100 and length_diff > len(baseline_text) * 0.1:
            return True

        # Check for new fields in JSON response
        try:
            baseline_json = json.loads(baseline_text)
            test_json = json.loads(test_text)

            def get_keys(obj, prefix=''):
                keys = set()
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        full_key = f"{prefix}.{key}" if prefix else key
                        keys.add(full_key)
                        if isinstance(value, (dict, list)):
                            keys.update(get_keys(value, full_key))
                elif isinstance(obj, list) and obj:
                    keys.update(get_keys(obj[0], prefix))
                return keys

            baseline_keys = get_keys(baseline_json)
            test_keys = get_keys(test_json)

            new_keys = test_keys - baseline_keys
            if new_keys:
                return True

        except (json.JSONDecodeError, TypeError):
            pass

        return False
