"""
BFLA (Broken Function Level Authorization) Detector

Detects vulnerabilities where users can access API functions/endpoints they shouldn't
have permission to access based on their role or authorization level.
"""

import re
import json
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse
import aiohttp

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity


class BFLADetector(BaseVulnerabilityDetector):
    """
    Detector for Broken Function Level Authorization (BFLA) vulnerabilities
    
    BFLA occurs when an API endpoint allows users to access functions or operations
    they shouldn't have permission to perform based on their role or authorization level.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        super().__init__(session, config)

        # Privileged endpoint patterns
        self.admin_patterns = [
            r'/admin',
            r'/administrator',
            r'/management',
            r'/manager',
            r'/control',
            r'/dashboard',
            r'/panel',
            r'/console'
        ]

        # Privileged operation keywords
        self.privileged_operations = [
            'admin', 'administrator', 'management', 'manager', 'control',
            'delete', 'remove', 'destroy', 'purge', 'drop',
            'create', 'add', 'insert', 'new',
            'update', 'edit', 'modify', 'change', 'patch',
            'config', 'configuration', 'settings', 'preferences',
            'user', 'users', 'account', 'accounts',
            'role', 'roles', 'permission', 'permissions',
            'system', 'server', 'service', 'services',
            'debug', 'test', 'internal', 'private'
        ]

        # HTTP methods that typically require higher privileges
        self.privileged_methods = ['POST', 'PUT', 'PATCH', 'DELETE']

        # Response patterns indicating successful privileged operations
        self.success_patterns = [
            r'"success":\s*true',
            r'"status":\s*"success"',
            r'"created":\s*true',
            r'"updated":\s*true',
            r'"deleted":\s*true',
            r'"message":\s*".*success.*"',
            r'"result":\s*".*success.*"',
        ]

        # Headers that might bypass authorization
        self.bypass_headers = {
            'X-Original-URL': None,
            'X-Rewrite-URL': None,
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'X-Host': 'localhost',
            'X-Custom-IP-Authorization': '127.0.0.1',
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Scheme': 'https',
            'X-Scheme': 'https',
            'X-Override-URL': None,
            'X-HTTP-Method-Override': None,
            'X-HTTP-Method': None,
        }

    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect BFLA vulnerabilities in the given endpoint
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of BFLA vulnerabilities found
        """
        results = []

        # Test direct access to privileged endpoints
        results.extend(await self._test_privileged_access(endpoint, method, params, headers, data))

        # Test HTTP method override bypass
        results.extend(await self._test_method_override(endpoint, method, params, headers, data))

        # Test header-based authorization bypass
        results.extend(await self._test_header_bypass(endpoint, method, params, headers, data))

        # Test privilege escalation through parameter manipulation
        results.extend(await self._test_parameter_privilege_escalation(endpoint, method, params, headers, data))

        return results

    async def _test_privileged_access(self, endpoint: str, method: str,
                                      params: Dict[str, Any] = None,
                                      headers: Dict[str, str] = None,
                                      data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test direct access to potentially privileged endpoints"""
        results = []

        # Check if current endpoint looks privileged
        is_privileged = self._is_privileged_endpoint(endpoint, method)

        if not is_privileged:
            return results

        # Try accessing without authentication
        no_auth_headers = headers.copy() if headers else {}
        auth_headers_to_remove = ['Authorization', 'Cookie', 'X-API-Key', 'X-Auth-Token']

        for auth_header in auth_headers_to_remove:
            no_auth_headers.pop(auth_header, None)

        # Make request without authentication
        response = await self.make_request(endpoint, method, params, no_auth_headers, data)
        await self.rate_limit_delay()

        if response and self._indicates_successful_access(response):
            evidence = {
                'endpoint': endpoint,
                'method': method,
                'status_code': response.status,
                'response_sample': getattr(response, '_text', '')[:500],
                'test_type': 'unauthenticated_access'
            }

            vulnerability = self.create_result(
                vuln_type="BFLA",
                severity=Severity.HIGH,
                title="Broken Function Level Authorization - Unauthenticated Access",
                description=f"The privileged endpoint {endpoint} can be accessed without authentication",
                endpoint=endpoint,
                method=method,
                evidence=evidence,
                remediation="Implement proper authentication and authorization checks for all privileged endpoints",
                cwe_id="CWE-862",
                owasp_category="API5:2023 Broken Function Level Authorization"
            )
            results.append(vulnerability)

        return results

    async def _test_method_override(self, endpoint: str, method: str,
                                    params: Dict[str, Any] = None,
                                    headers: Dict[str, str] = None,
                                    data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test HTTP method override for privilege escalation"""
        results = []

        if method in self.privileged_methods:
            return results  # Already testing a privileged method

        # Test method override headers
        override_headers = [
            'X-HTTP-Method-Override',
            'X-HTTP-Method',
            'X-Method-Override',
            '_method'
        ]

        for privileged_method in self.privileged_methods:
            for override_header in override_headers:
                test_headers = headers.copy() if headers else {}
                test_headers[override_header] = privileged_method

                # Also test as form parameter for POST requests
                test_params = params.copy() if params else {}
                if override_header == '_method':
                    test_params['_method'] = privileged_method

                response = await self.make_request(endpoint, method, test_params, test_headers, data)
                await self.rate_limit_delay()

                if response and self._indicates_privileged_operation_success(response, privileged_method):
                    evidence = {
                        'endpoint': endpoint,
                        'original_method': method,
                        'override_method': privileged_method,
                        'override_header': override_header,
                        'status_code': response.status,
                        'response_sample': getattr(response, '_text', '')[:500]
                    }

                    vulnerability = self.create_result(
                        vuln_type="BFLA",
                        severity=Severity.HIGH,
                        title=f"HTTP Method Override Bypass - {privileged_method}",
                        description=f"Bypassed method restrictions using {override_header} header to perform {privileged_method} operation",
                        endpoint=endpoint,
                        method=method,
                        evidence=evidence,
                        remediation="Disable HTTP method override headers or implement proper validation",
                        cwe_id="CWE-20",
                        owasp_category="API5:2023 Broken Function Level Authorization"
                    )
                    results.append(vulnerability)

        return results

    async def _test_header_bypass(self, endpoint: str, method: str,
                                  params: Dict[str, Any] = None,
                                  headers: Dict[str, str] = None,
                                  data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test various headers that might bypass authorization"""
        results = []

        base_response = await self.make_request(endpoint, method, params, headers, data)
        if not base_response:
            return results

        base_status = base_response.status
        base_text = getattr(base_response, '_text', '')

        for bypass_header, bypass_value in self.bypass_headers.items():
            test_headers = headers.copy() if headers else {}

            if bypass_value is not None:
                test_headers[bypass_header] = bypass_value
            else:
                # For headers like X-Original-URL, use the same endpoint
                test_headers[bypass_header] = endpoint

            response = await self.make_request(endpoint, method, params, test_headers, data)
            await self.rate_limit_delay()

            if not response:
                continue

            # Check if bypass was successful
            if self._detect_authorization_bypass(base_response, base_text, response):
                evidence = {
                    'endpoint': endpoint,
                    'method': method,
                    'bypass_header': bypass_header,
                    'bypass_value': bypass_value or endpoint,
                    'original_status': base_status,
                    'bypass_status': response.status,
                    'response_sample': getattr(response, '_text', '')[:500]
                }

                vulnerability = self.create_result(
                    vuln_type="BFLA",
                    severity=Severity.MEDIUM,
                    title=f"Authorization Bypass via {bypass_header} Header",
                    description=f"Authorization can be bypassed using the {bypass_header} header",
                    endpoint=endpoint,
                    method=method,
                    evidence=evidence,
                    remediation=f"Remove or properly validate the {bypass_header} header processing",
                    cwe_id="CWE-863",
                    owasp_category="API5:2023 Broken Function Level Authorization"
                )
                results.append(vulnerability)

        return results

    async def _test_parameter_privilege_escalation(self, endpoint: str, method: str,
                                                   params: Dict[str, Any] = None,
                                                   headers: Dict[str, str] = None,
                                                   data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test privilege escalation through parameter manipulation"""
        results = []

        privilege_params = {
            'admin': ['true', '1', 'yes'],
            'is_admin': ['true', '1', 'yes'],
            'role': ['admin', 'administrator', 'root', 'superuser'],
            'user_role': ['admin', 'administrator', 'root'],
            'privilege': ['admin', 'high', 'elevated'],
            'level': ['admin', '999', '100'],
            'access_level': ['admin', 'full', 'all'],
            'permissions': ['all', 'admin', 'full'],
            'scope': ['admin', 'global', 'all']
        }

        # Test query parameters
        if params:
            for param_name, test_values in privilege_params.items():
                for test_value in test_values:
                    test_params = params.copy()
                    test_params[param_name] = test_value

                    response = await self.make_request(endpoint, method, test_params, headers, data)
                    await self.rate_limit_delay()

                    if response and self._indicates_privilege_escalation(response):
                        evidence = {
                            'endpoint': endpoint,
                            'method': method,
                            'escalation_param': param_name,
                            'escalation_value': test_value,
                            'status_code': response.status,
                            'response_sample': getattr(response, '_text', '')[:500]
                        }

                        vulnerability = self.create_result(
                            vuln_type="BFLA",
                            severity=Severity.HIGH,
                            title=f"Privilege Escalation via {param_name} Parameter",
                            description=f"Privilege escalation achieved by setting {param_name}={test_value}",
                            endpoint=endpoint,
                            method=method,
                            evidence=evidence,
                            remediation="Implement proper parameter validation and authorization checks",
                            cwe_id="CWE-269",
                            owasp_category="API5:2023 Broken Function Level Authorization"
                        )
                        results.append(vulnerability)

        # Test JSON body parameters
        if data and method in ['POST', 'PUT', 'PATCH']:
            for param_name, test_values in privilege_params.items():
                for test_value in test_values:
                    test_data = data.copy()
                    test_data[param_name] = test_value

                    response = await self.make_request(endpoint, method, params, headers, test_data)
                    await self.rate_limit_delay()

                    if response and self._indicates_privilege_escalation(response):
                        evidence = {
                            'endpoint': endpoint,
                            'method': method,
                            'escalation_param': param_name,
                            'escalation_value': test_value,
                            'location': 'request_body',
                            'status_code': response.status,
                            'response_sample': getattr(response, '_text', '')[:500]
                        }

                        vulnerability = self.create_result(
                            vuln_type="BFLA",
                            severity=Severity.HIGH,
                            title=f"Privilege Escalation via {param_name} in Request Body",
                            description=f"Privilege escalation achieved by setting {param_name}={test_value} in request body",
                            endpoint=endpoint,
                            method=method,
                            evidence=evidence,
                            remediation="Implement proper parameter validation and authorization checks for request body",
                            cwe_id="CWE-269",
                            owasp_category="API5:2023 Broken Function Level Authorization"
                        )
                        results.append(vulnerability)

        return results

    def _is_privileged_endpoint(self, endpoint: str, method: str) -> bool:
        """Check if an endpoint appears to require elevated privileges"""
        endpoint_lower = endpoint.lower()

        # Check for admin patterns in URL
        for pattern in self.admin_patterns:
            if pattern in endpoint_lower:
                return True

        # Check for privileged operations in URL
        for operation in self.privileged_operations:
            if operation in endpoint_lower:
                return True

        # Check if using privileged HTTP method
        if method in self.privileged_methods:
            return True

        return False

    def _indicates_successful_access(self, response: aiohttp.ClientResponse) -> bool:
        """Check if response indicates successful access to a privileged function"""
        if response.status in [200, 201, 202, 204]:
            return True

        # Check response content for success indicators
        response_text = getattr(response, '_text', '')
        for pattern in self.success_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _indicates_privileged_operation_success(self, response: aiohttp.ClientResponse,
                                                method: str) -> bool:
        """Check if response indicates successful privileged operation"""
        response_text = getattr(response, '_text', '')

        # Success status codes
        if response.status in [200, 201, 202, 204]:
            # Look for method-specific success indicators
            method_patterns = {
                'POST': [r'created', r'added', r'inserted'],
                'PUT': [r'updated', r'modified', r'changed'],
                'PATCH': [r'updated', r'patched', r'modified'],
                'DELETE': [r'deleted', r'removed', r'destroyed']
            }

            patterns = method_patterns.get(method, [])
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True

            # General success patterns
            for pattern in self.success_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True

        return False

    def _detect_authorization_bypass(self, base_response: aiohttp.ClientResponse,
                                     base_text: str,
                                     test_response: aiohttp.ClientResponse) -> bool:
        """Detect if authorization was bypassed"""
        test_text = getattr(test_response, '_text', '')

        # Status code changed from unauthorized to success
        if base_response.status in [401, 403] and test_response.status in [200, 201, 202, 204]:
            return True

        # Content changed significantly (got more data)
        if (len(test_text) > len(base_text) * 1.5 and
                len(test_text) > 100 and
                test_response.status in [200, 201, 202, 204]):
            return True

        # Look for admin/privileged content in response
        privileged_indicators = [
            r'admin', r'administrator', r'management', r'dashboard',
            r'delete', r'remove', r'create', r'update', r'config'
        ]

        for indicator in privileged_indicators:
            if (re.search(indicator, test_text, re.IGNORECASE) and
                    not re.search(indicator, base_text, re.IGNORECASE)):
                return True

        return False

    def _indicates_privilege_escalation(self, response: aiohttp.ClientResponse) -> bool:
        """Check if response indicates successful privilege escalation"""
        if response.status not in [200, 201, 202, 204]:
            return False

        response_text = getattr(response, '_text', '')

        # Look for admin/elevated privilege indicators in response
        escalation_indicators = [
            r'"role":\s*"admin"',
            r'"is_admin":\s*true',
            r'"admin":\s*true',
            r'"privilege":\s*"admin"',
            r'"access_level":\s*"admin"',
            r'"permissions":\s*\[.*"admin".*\]',
            r'administrator',
            r'elevated.*privilege',
            r'admin.*access'
        ]

        for indicator in escalation_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True

        return False
