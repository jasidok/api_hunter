"""
Technology Fingerprinting Module

Identifies web frameworks, servers, and technologies used by the API through
header analysis, response patterns, and behavior detection.
"""

import re
import hashlib
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin
import httpx

from .base_discoverer import BaseDiscoverer, DiscoveredEndpoint, DiscoveryResult


class TechnologyFingerprinter(BaseDiscoverer):
    """Fingerprints technologies used by the API"""

    # Common fingerprinting paths
    FINGERPRINT_PATHS = [
        '/',
        '/robots.txt',
        '/sitemap.xml',
        '/favicon.ico',
        '/manifest.json',
        '/.well-known/security.txt',
        '/health',
        '/status',
        '/version',
        '/info',
        '/debug',
        '/admin',
        '/api',
        '/swagger.json',
        '/openapi.json',
        '/graphql',
        '/.env',
        '/config.json',
        '/package.json',
    ]

    # Framework signatures
    FRAMEWORK_SIGNATURES = {
        # Web Frameworks
        'express': {
            'headers': ['x-powered-by'],
            'header_values': ['express'],
            'body_patterns': [r'express', r'node\.js'],
            'error_patterns': [r'at\s+\w+\s+\([^)]*:\d+:\d+\)']
        },
        'django': {
            'headers': ['server'],
            'header_values': ['django'],
            'body_patterns': [r'django', r'CSRF token'],
            'error_patterns': [r'Django Version:', r'Request Method:', r'Exception Type:']
        },
        'flask': {
            'headers': ['server'],
            'header_values': ['werkzeug', 'flask'],
            'body_patterns': [r'flask', r'werkzeug'],
            'error_patterns': [r'Traceback \(most recent call last\):', r'File.*flask']
        },
        'fastapi': {
            'headers': ['server'],
            'header_values': ['fastapi', 'uvicorn'],
            'body_patterns': [r'fastapi', r'uvicorn'],
            'error_patterns': [r'"detail":', r'FastAPI']
        },
        'rails': {
            'headers': ['x-powered-by', 'server'],
            'header_values': ['phusion passenger', 'ruby'],
            'body_patterns': [r'ruby on rails', r'rails'],
            'error_patterns': [r'ActiveRecord::', r'ActionController::']
        },
        'spring': {
            'headers': ['server'],
            'header_values': ['apache-coyote', 'tomcat'],
            'body_patterns': [r'spring framework', r'springframework'],
            'error_patterns': [r'org\.springframework', r'java\.lang\.']
        },
        'asp.net': {
            'headers': ['x-powered-by', 'x-aspnet-version', 'server'],
            'header_values': ['asp.net', 'microsoft-iis'],
            'body_patterns': [r'asp\.net', r'\.net framework'],
            'error_patterns': [r'System\.', r'Microsoft\.']
        },
        'laravel': {
            'headers': ['x-powered-by'],
            'header_values': ['php'],
            'body_patterns': [r'laravel', r'illuminate\\'],
            'error_patterns': [r'Illuminate\\', r'Laravel\\']
        },
        'gin': {
            'headers': ['server'],
            'header_values': ['gin'],
            'body_patterns': [r'gin-gonic', r'golang'],
            'error_patterns': [r'gin\.Context', r'github\.com/gin-gonic']
        }
    }

    # Server signatures
    SERVER_SIGNATURES = {
        'nginx': {
            'headers': ['server'],
            'header_values': ['nginx'],
            'body_patterns': [r'nginx']
        },
        'apache': {
            'headers': ['server'],
            'header_values': ['apache'],
            'body_patterns': [r'apache']
        },
        'iis': {
            'headers': ['server'],
            'header_values': ['microsoft-iis', 'iis'],
            'body_patterns': [r'microsoft-iis', r'iis']
        },
        'cloudflare': {
            'headers': ['server', 'cf-ray'],
            'header_values': ['cloudflare'],
            'body_patterns': [r'cloudflare']
        },
        'aws-alb': {
            'headers': ['server'],
            'header_values': ['awselb'],
            'body_patterns': []
        }
    }

    # Database signatures (from error messages)
    DATABASE_SIGNATURES = {
        'mysql': [r'mysql', r'MariaDB', r'SQLSTATE\[HY000\]'],
        'postgresql': [r'postgresql', r'postgres', r'SQLSTATE\[.*\]'],
        'mongodb': [r'mongodb', r'mongo', r'MongoError'],
        'redis': [r'redis', r'WRONGTYPE', r'NOAUTH'],
        'elasticsearch': [r'elasticsearch', r'elastic', r'"type":"es_exception"'],
        'sqlite': [r'sqlite', r'database is locked', r'no such table']
    }

    # Cloud provider signatures
    CLOUD_SIGNATURES = {
        'aws': {
            'headers': ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-request-id'],
            'header_values': ['amazon', 'aws'],
            'body_patterns': [r'amazonaws\.com', r'aws\.amazon\.com']
        },
        'gcp': {
            'headers': ['server'],
            'header_values': ['google frontend', 'gfe'],
            'body_patterns': [r'googleapis\.com', r'cloud\.google\.com']
        },
        'azure': {
            'headers': ['server'],
            'header_values': ['microsoft-azure', 'azure'],
            'body_patterns': [r'azure\.microsoft\.com', r'azurewebsites\.net']
        },
        'heroku': {
            'headers': ['server'],
            'header_values': ['heroku'],
            'body_patterns': [r'herokuapp\.com']
        },
        'vercel': {
            'headers': ['server', 'x-vercel-id'],
            'header_values': ['vercel'],
            'body_patterns': [r'vercel\.app', r'vercel\.com']
        }
    }

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        super().__init__(client, base_url)
        self.detected_technologies: Set[str] = set()
        self.version_info: Dict[str, str] = {}
        self.response_fingerprints: List[Dict[str, Any]] = []

    def get_discovery_type(self) -> str:
        return "Technology Fingerprinting"

    async def discover(self) -> DiscoveryResult:
        """
        Perform technology fingerprinting
        
        Returns:
            DiscoveryResult with detected technologies
        """
        endpoints: List[DiscoveredEndpoint] = []
        schemas: List[Dict[str, Any]] = []
        technologies: List[str] = []
        documentation_urls: List[str] = []

        # Collect fingerprinting data
        await self._collect_fingerprints()

        # Analyze collected data
        await self._analyze_fingerprints()

        # Convert detected technologies to list
        technologies = list(self.detected_technologies)

        return DiscoveryResult(
            endpoints=endpoints,
            schemas=schemas,
            technologies=technologies,
            documentation_urls=documentation_urls,
            errors=self.errors
        )

    async def _collect_fingerprints(self) -> None:
        """Collect fingerprinting data from various endpoints"""

        for path in self.FINGERPRINT_PATHS:
            try:
                response = await self._make_request(path)
                if response:
                    fingerprint = {
                        'path': path,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'body': response.text[:10000] if response.text else '',  # First 10KB
                        'response_time': getattr(response, 'elapsed', None)
                    }
                    self.response_fingerprints.append(fingerprint)

                    # Quick analysis for each response
                    await self._analyze_single_response(fingerprint)

            except Exception as e:
                self.errors.append(f"Error fingerprinting {path}: {str(e)}")

    async def _analyze_single_response(self, fingerprint: Dict[str, Any]) -> None:
        """Analyze a single response for technology indicators"""

        headers = fingerprint['headers']
        body = fingerprint['body'].lower()

        # Check framework signatures
        for framework, signature in self.FRAMEWORK_SIGNATURES.items():
            if self._matches_signature(headers, body, signature):
                self.detected_technologies.add(framework)

                # Extract version information
                version = self._extract_version(headers, body, framework)
                if version:
                    self.version_info[framework] = version

        # Check server signatures
        for server, signature in self.SERVER_SIGNATURES.items():
            if self._matches_signature(headers, body, signature):
                self.detected_technologies.add(server)

                # Extract version information
                version = self._extract_version(headers, body, server)
                if version:
                    self.version_info[server] = version

        # Check cloud provider signatures
        for provider, signature in self.CLOUD_SIGNATURES.items():
            if self._matches_signature(headers, body, signature):
                self.detected_technologies.add(provider)

        # Check for database signatures in error messages
        if fingerprint['status_code'] >= 500:
            for db, patterns in self.DATABASE_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        self.detected_technologies.add(db)
                        break

    def _matches_signature(
            self,
            headers: Dict[str, str],
            body: str,
            signature: Dict[str, List[str]]
    ) -> bool:
        """Check if response matches a technology signature"""

        # Check headers
        if 'headers' in signature:
            for header_name in signature['headers']:
                if header_name.lower() in [h.lower() for h in headers.keys()]:
                    # If header_values specified, check values too
                    if 'header_values' in signature:
                        header_value = headers.get(header_name, '').lower()
                        if any(val.lower() in header_value for val in signature['header_values']):
                            return True
                    else:
                        return True

        # Check header values
        if 'header_values' in signature:
            all_header_values = ' '.join(headers.values()).lower()
            if any(val.lower() in all_header_values for val in signature['header_values']):
                return True

        # Check body patterns
        if 'body_patterns' in signature:
            for pattern in signature['body_patterns']:
                if re.search(pattern, body, re.IGNORECASE):
                    return True

        # Check error patterns (typically in 4xx/5xx responses)
        if 'error_patterns' in signature:
            for pattern in signature['error_patterns']:
                if re.search(pattern, body, re.IGNORECASE):
                    return True

        return False

    def _extract_version(self, headers: Dict[str, str], body: str, technology: str) -> Optional[str]:
        """Extract version information for a detected technology"""

        # Version patterns for different technologies
        version_patterns = {
            'nginx': [
                r'nginx/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'nginx\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'apache': [
                r'Apache/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'apache\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'express': [
                r'express["\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'"express":\s*"([^"]+)"'
            ],
            'django': [
                r'Django\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'django["\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'flask': [
                r'Flask["\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'flask["\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ],
            'spring': [
                r'Spring["\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'springframework["\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
            ]
        }

        # Check headers first
        server_header = headers.get('server', '')
        x_powered_by = headers.get('x-powered-by', '')

        combined_headers = f"{server_header} {x_powered_by}".lower()

        # Look for version in headers
        if technology in version_patterns:
            for pattern in version_patterns[technology]:
                match = re.search(pattern, combined_headers, re.IGNORECASE)
                if match:
                    return match.group(1)

                # Also check body
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return match.group(1)

        # Generic version pattern
        generic_patterns = [
            rf'{technology}["\s/]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            rf'"{technology}":\s*"([^"]+)"',
            rf'{technology}\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
        ]

        for pattern in generic_patterns:
            match = re.search(pattern, combined_headers, re.IGNORECASE)
            if match:
                return match.group(1)

            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    async def _analyze_fingerprints(self) -> None:
        """Perform additional analysis on collected fingerprints"""

        # Analyze response timing patterns
        self._analyze_timing_patterns()

        # Analyze response size patterns
        self._analyze_size_patterns()

        # Analyze common security headers
        self._analyze_security_headers()

        # Analyze error page patterns
        self._analyze_error_patterns()

    def _analyze_timing_patterns(self) -> None:
        """Analyze response timing patterns for technology hints"""

        if not self.response_fingerprints:
            return

        # Calculate average response times
        total_time = 0
        count = 0

        for fp in self.response_fingerprints:
            if fp.get('response_time'):
                total_time += fp['response_time'].total_seconds()
                count += 1

        if count > 0:
            avg_time = total_time / count

            # Very fast responses might indicate static file serving or CDN
            if avg_time < 0.05:  # 50ms
                self.detected_technologies.add('CDN/Cache')

            # Very slow responses might indicate database-heavy applications
            elif avg_time > 2.0:  # 2 seconds
                self.detected_technologies.add('Database-heavy')

    def _analyze_size_patterns(self) -> None:
        """Analyze response size patterns"""

        for fp in self.response_fingerprints:
            body_size = len(fp['body'])

            # Very small responses might be microservices
            if body_size < 100 and fp['status_code'] == 200:
                self.detected_technologies.add('Microservice')

            # Large JSON responses might indicate REST APIs
            elif body_size > 10000 and 'application/json' in fp['headers'].get('content-type', ''):
                self.detected_technologies.add('REST API')

    def _analyze_security_headers(self) -> None:
        """Analyze security headers for technology hints"""

        security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection'
        ]

        security_count = 0

        for fp in self.response_fingerprints:
            headers = {k.lower(): v for k, v in fp['headers'].items()}

            for sec_header in security_headers:
                if sec_header in headers:
                    security_count += 1

        # High security header usage might indicate enterprise applications
        if security_count > len(security_headers) * 0.7:
            self.detected_technologies.add('Enterprise Security')

    def _analyze_error_patterns(self) -> None:
        """Analyze error response patterns"""

        for fp in self.response_fingerprints:
            if fp['status_code'] >= 400:
                body = fp['body'].lower()

                # Look for common error page frameworks
                if 'bootstrap' in body or 'jquery' in body:
                    self.detected_technologies.add('Frontend Framework')

                if 'react' in body:
                    self.detected_technologies.add('React')

                if 'angular' in body:
                    self.detected_technologies.add('Angular')

                if 'vue' in body:
                    self.detected_technologies.add('Vue.js')
