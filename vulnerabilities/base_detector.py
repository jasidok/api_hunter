"""
Base Vulnerability Detector

Abstract base class for all vulnerability detectors in API Hunter.
Provides common interface and functionality for vulnerability detection.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime
import asyncio
import aiohttp
import json
import re


class Severity(Enum):
    """Vulnerability severity levels following CVSS guidelines"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityResult:
    """Container for vulnerability detection results"""
    vuln_type: str
    severity: Severity
    title: str
    description: str
    endpoint: str
    method: str
    evidence: Dict[str, Any]
    remediation: str
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    discovered_at: datetime = None

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow()


class BaseVulnerabilityDetector(ABC):
    """
    Abstract base class for all vulnerability detectors
    
    Each detector should inherit from this class and implement the detect method
    to search for specific vulnerability types.
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict[str, Any] = None):
        self.session = session
        self.config = config or {}
        self.results: List[VulnerabilityResult] = []

        # Common detection settings
        self.timeout = self.config.get('timeout', 30)
        self.max_retries = self.config.get('max_retries', 3)
        self.rate_limit = self.config.get('rate_limit', 10)  # requests per second

        # Common payloads and patterns
        self.common_patterns = {
            'error_messages': [
                r'ORA-\d+',  # Oracle errors
                r'Microsoft.*ODBC.*SQL Server',  # SQL Server errors
                r'MySQL.*syntax.*error',  # MySQL errors
                r'PostgreSQL.*ERROR',  # PostgreSQL errors
                r'sqlite3\.OperationalError',  # SQLite errors
                r'MongoDB.*Error',  # MongoDB errors
                r'java\.sql\.SQLException',  # Java SQL errors
                r'System\.Data\.SqlClient\.SqlException',  # .NET SQL errors
            ],
            'sensitive_data': [
                r'password["\']?\s*[:=]\s*["\']?[^"\',\s]+',
                r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\',\s]+',
                r'secret["\']?\s*[:=]\s*["\']?[^"\',\s]+',
                r'token["\']?\s*[:=]\s*["\']?[^"\',\s]+',
                r'bearer\s+[a-zA-Z0-9\-._~+/]+=*',
                r'-----BEGIN.*PRIVATE KEY-----',
            ]
        }

    @abstractmethod
    async def detect(self, endpoint: str, method: str = "GET",
                     params: Dict[str, Any] = None,
                     headers: Dict[str, str] = None,
                     data: Dict[str, Any] = None) -> List[VulnerabilityResult]:
        """
        Detect vulnerabilities for a specific endpoint
        
        Args:
            endpoint: The API endpoint to test
            method: HTTP method to use
            params: Query parameters
            headers: HTTP headers
            data: Request body data
            
        Returns:
            List of vulnerability results found
        """
        pass

    async def make_request(self, url: str, method: str = "GET",
                           params: Dict[str, Any] = None,
                           headers: Dict[str, str] = None,
                           data: Dict[str, Any] = None,
                           timeout: int = None) -> Optional[aiohttp.ClientResponse]:
        """
        Make an HTTP request with error handling and retries
        
        Args:
            url: Target URL
            method: HTTP method
            params: Query parameters
            headers: HTTP headers
            data: Request body
            timeout: Request timeout
            
        Returns:
            Response object or None if failed
        """
        timeout = timeout or self.timeout
        headers = headers or {}

        # Add common headers
        if 'User-Agent' not in headers:
            headers['User-Agent'] = 'API-Hunter/1.0 (Security Scanner)'

        for attempt in range(self.max_retries):
            try:
                async with self.session.request(
                        method=method,
                        url=url,
                        params=params,
                        headers=headers,
                        json=data if data and method in ['POST', 'PUT', 'PATCH'] else None,
                        timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    # Read response body for analysis
                    response_text = await response.text()
                    response._text = response_text
                    return response

            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return None
                await asyncio.sleep(2 ** attempt)  # Exponential backoff

            except Exception as e:
                if attempt == self.max_retries - 1:
                    return None
                await asyncio.sleep(1)

        return None

    def analyze_response(self, response: aiohttp.ClientResponse,
                         response_text: str) -> Dict[str, Any]:
        """
        Analyze HTTP response for vulnerability indicators
        
        Args:
            response: HTTP response object
            response_text: Response body text
            
        Returns:
            Dictionary of analysis results
        """
        analysis = {
            'status_code': response.status,
            'headers': dict(response.headers),
            'content_length': len(response_text),
            'response_time': getattr(response, '_response_time', 0),
            'error_indicators': [],
            'sensitive_data': [],
            'security_headers': {},
            'content_type': response.headers.get('Content-Type', ''),
        }

        # Check for error patterns
        for pattern in self.common_patterns['error_messages']:
            if re.search(pattern, response_text, re.IGNORECASE):
                analysis['error_indicators'].append(pattern)

        # Check for sensitive data exposure
        for pattern in self.common_patterns['sensitive_data']:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                analysis['sensitive_data'].extend(matches)

        # Check security headers
        security_headers = [
            'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Content-Security-Policy', 'Access-Control-Allow-Origin'
        ]

        for header in security_headers:
            if header in response.headers:
                analysis['security_headers'][header] = response.headers[header]

        return analysis

    def create_result(self, vuln_type: str, severity: Severity, title: str,
                      description: str, endpoint: str, method: str,
                      evidence: Dict[str, Any], remediation: str,
                      cvss_score: Optional[float] = None,
                      cwe_id: Optional[str] = None,
                      owasp_category: Optional[str] = None) -> VulnerabilityResult:
        """
        Create a standardized vulnerability result
        
        Args:
            vuln_type: Type of vulnerability
            severity: Severity level
            title: Vulnerability title
            description: Detailed description
            endpoint: Affected endpoint
            method: HTTP method
            evidence: Supporting evidence
            remediation: Remediation guidance
            cvss_score: CVSS score if available
            cwe_id: CWE identifier if applicable
            owasp_category: OWASP API Top 10 category
            
        Returns:
            VulnerabilityResult object
        """
        result = VulnerabilityResult(
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            remediation=remediation,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            owasp_category=owasp_category
        )

        self.results.append(result)
        return result

    async def rate_limit_delay(self):
        """Apply rate limiting between requests"""
        if self.rate_limit > 0:
            delay = 1.0 / self.rate_limit
            await asyncio.sleep(delay)

    def get_results(self) -> List[VulnerabilityResult]:
        """Get all vulnerability results found by this detector"""
        return self.results

    def clear_results(self):
        """Clear all stored results"""
        self.results.clear()
