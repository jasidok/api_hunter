"""
Burp Suite Integration Plugin

Provides integration with Burp Suite Professional for sending findings
and importing scan results.
"""

import json
import requests
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

from ..base_plugin import IntegrationPlugin, PluginInfo, PluginType


class BurpIntegrationPlugin(IntegrationPlugin):
    """
    Burp Suite Professional integration plugin.
    
    Features:
    - Send vulnerability findings to Burp Suite
    - Import scan results from Burp Suite
    - Synchronize target scopes
    - Export Burp findings to API Hunter format
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Burp integration plugin.
        
        Args:
            config: Plugin configuration including Burp Suite API settings
        """
        super().__init__(config)
        self.burp_url = self.config.get('burp_url', 'http://localhost:1337')
        self.api_key = self.config.get('api_key', '')
        self.session = None
        self._test_connection = True

    @property
    def plugin_info(self) -> PluginInfo:
        """Return plugin metadata."""
        return PluginInfo(
            name="burp_integration",
            version="1.0.0",
            description="Burp Suite Professional integration for sending findings and importing data",
            author="API Hunter Team",
            plugin_type=PluginType.INTEGRATION,
            dependencies=["requests"],
            config_schema={
                "required": ["burp_url"],
                "optional": ["api_key", "timeout", "verify_ssl"],
                "properties": {
                    "burp_url": {"type": "string", "description": "Burp Suite API URL"},
                    "api_key": {"type": "string", "description": "Burp Suite API key"},
                    "timeout": {"type": "integer", "default": 30},
                    "verify_ssl": {"type": "boolean", "default": True}
                }
            }
        )

    async def initialize(self) -> bool:
        """Initialize the plugin and test connection to Burp Suite."""
        try:
            # Create session with timeout and SSL settings
            self.session = requests.Session()
            self.session.timeout = self.config.get('timeout', 30)
            self.session.verify = self.config.get('verify_ssl', True)

            # Add API key to headers if provided
            if self.api_key:
                self.session.headers.update({
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json'
                })

            # Test connection to Burp Suite
            if self._test_connection:
                await self._test_burp_connection()

            return True

        except Exception as e:
            print(f"Failed to initialize Burp integration: {e}")
            return False

    async def cleanup(self) -> None:
        """Clean up plugin resources."""
        if self.session:
            self.session.close()
            self.session = None

    async def _test_burp_connection(self) -> bool:
        """Test connection to Burp Suite API."""
        try:
            # Try to get Burp version info
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.get(urljoin(self.burp_url, '/burp/versions'))
            )

            if response.status_code == 200:
                version_info = response.json()
                print(f"Connected to Burp Suite {version_info.get('burp', 'Unknown version')}")
                return True
            else:
                print(f"Burp Suite API returned status {response.status_code}")
                return False

        except Exception as e:
            print(f"Failed to connect to Burp Suite: {e}")
            return False

    async def send_findings(self, findings: List[Dict[str, Any]]) -> bool:
        """
        Send vulnerability findings to Burp Suite.
        
        Args:
            findings: List of vulnerability findings from API Hunter
            
        Returns:
            True if successful, False otherwise
        """
        if not self.session:
            return False

        try:
            # Convert API Hunter findings to Burp format
            burp_findings = []
            for finding in findings:
                burp_finding = self._convert_to_burp_format(finding)
                if burp_finding:
                    burp_findings.append(burp_finding)

            if not burp_findings:
                return True  # Nothing to send

            # Send findings to Burp Suite
            endpoint = urljoin(self.burp_url, '/burp/scanner/issues')

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(endpoint, json={'issues': burp_findings})
            )

            if response.status_code in [200, 201]:
                print(f"Successfully sent {len(burp_findings)} findings to Burp Suite")
                return True
            else:
                print(f"Failed to send findings to Burp Suite: {response.status_code}")
                return False

        except Exception as e:
            print(f"Error sending findings to Burp Suite: {e}")
            return False

    def _convert_to_burp_format(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert API Hunter finding to Burp Suite issue format.
        
        Args:
            finding: API Hunter vulnerability finding
            
        Returns:
            Burp Suite formatted issue or None if conversion fails
        """
        try:
            # Map severity levels
            severity_map = {
                'CRITICAL': 'High',
                'HIGH': 'High',
                'MEDIUM': 'Medium',
                'LOW': 'Low',
                'INFO': 'Information'
            }

            # Map confidence levels
            confidence_map = {
                'CONFIRMED': 'Certain',
                'LIKELY': 'Firm',
                'POSSIBLE': 'Tentative'
            }

            burp_issue = {
                'type_index': self._get_burp_issue_type(finding.get('owasp_category', 'Unknown')),
                'name': finding.get('title', 'API Hunter Finding'),
                'host': self._extract_host_from_endpoint(finding.get('affected_endpoint', '')),
                'path': self._extract_path_from_endpoint(finding.get('affected_endpoint', '')),
                'severity': severity_map.get(finding.get('severity', 'LOW'), 'Low'),
                'confidence': confidence_map.get(finding.get('confidence', 'POSSIBLE'), 'Tentative'),
                'issue_background': finding.get('description', ''),
                'remediation_background': finding.get('remediation', ''),
                'issue_detail': self._format_issue_details(finding),
                'remediation_detail': finding.get('remediation', ''),
                'references': self._format_references(finding.get('references', [])),
            }

            # Add request/response data if available
            if finding.get('request_data'):
                burp_issue['request'] = self._format_request_data(finding['request_data'])

            if finding.get('response_data'):
                burp_issue['response'] = self._format_response_data(finding['response_data'])

            return burp_issue

        except Exception as e:
            print(f"Error converting finding to Burp format: {e}")
            return None

    def _get_burp_issue_type(self, owasp_category: str) -> int:
        """
        Map OWASP category to Burp Suite issue type index.
        
        Args:
            owasp_category: OWASP vulnerability category
            
        Returns:
            Burp Suite issue type index
        """
        # Common Burp Suite issue type mappings
        type_map = {
            'Injection': 1048832,  # SQL injection
            'Broken Authentication': 2097408,  # Authentication bypass
            'Sensitive Data Exposure': 5242880,  # Information disclosure
            'XML External Entities': 1048576,  # XXE
            'Broken Access Control': 4194304,  # Access control issues
            'Security Misconfiguration': 6291456,  # Configuration issues
            'Cross-Site Scripting': 524288,  # XSS
            'Insecure Deserialization': 8388608,  # Deserialization
            'Using Components with Known Vulnerabilities': 7340032,  # Vulnerable components
            'Insufficient Logging & Monitoring': 9437184,  # Logging issues
        }

        return type_map.get(owasp_category, 134217728)  # Default to "External service interaction"

    def _extract_host_from_endpoint(self, endpoint: str) -> str:
        """Extract host from endpoint URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return endpoint

    def _extract_path_from_endpoint(self, endpoint: str) -> str:
        """Extract path from endpoint URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            return parsed.path + ('?' + parsed.query if parsed.query else '')
        except:
            return "/"

    def _format_issue_details(self, finding: Dict[str, Any]) -> str:
        """Format detailed issue information for Burp Suite."""
        details = []

        if finding.get('description'):
            details.append(f"Description: {finding['description']}")

        if finding.get('cvss_score'):
            details.append(f"CVSS Score: {finding['cvss_score']}")

        if finding.get('cwe_id'):
            details.append(f"CWE ID: {finding['cwe_id']}")

        if finding.get('evidence'):
            details.append("Evidence:")
            for i, evidence in enumerate(finding['evidence'][:3], 1):
                details.append(f"  {i}. {evidence}")

        return "\n".join(details)

    def _format_references(self, references: List[str]) -> str:
        """Format references for Burp Suite."""
        if not references:
            return ""

        return "\n".join([f"• {ref}" for ref in references])

    def _format_request_data(self, request_data: Dict[str, Any]) -> str:
        """Format request data for Burp Suite."""
        try:
            # Build HTTP request format
            method = request_data.get('method', 'GET')
            path = request_data.get('path', '/')
            headers = request_data.get('headers', {})
            body = request_data.get('body', '')

            request_lines = [f"{method} {path} HTTP/1.1"]

            for header, value in headers.items():
                request_lines.append(f"{header}: {value}")

            request_lines.append("")  # Empty line before body

            if body:
                request_lines.append(str(body))

            return "\r\n".join(request_lines)

        except Exception:
            return str(request_data)

    def _format_response_data(self, response_data: Dict[str, Any]) -> str:
        """Format response data for Burp Suite."""
        try:
            # Build HTTP response format
            status_code = response_data.get('status_code', 200)
            headers = response_data.get('headers', {})
            body = response_data.get('body', '')

            response_lines = [f"HTTP/1.1 {status_code} OK"]

            for header, value in headers.items():
                response_lines.append(f"{header}: {value}")

            response_lines.append("")  # Empty line before body

            if body:
                response_lines.append(str(body))

            return "\r\n".join(response_lines)

        except Exception:
            return str(response_data)

    async def import_data(self) -> List[Dict[str, Any]]:
        """
        Import scan results from Burp Suite.
        
        Returns:
            List of findings imported from Burp Suite
        """
        if not self.session:
            return []

        try:
            # Get issues from Burp Suite
            endpoint = urljoin(self.burp_url, '/burp/scanner/issues')

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.get(endpoint)
            )

            if response.status_code != 200:
                print(f"Failed to import data from Burp Suite: {response.status_code}")
                return []

            burp_issues = response.json().get('issues', [])

            # Convert Burp issues to API Hunter format
            api_hunter_findings = []
            for issue in burp_issues:
                finding = self._convert_from_burp_format(issue)
                if finding:
                    api_hunter_findings.append(finding)

            print(f"Imported {len(api_hunter_findings)} findings from Burp Suite")
            return api_hunter_findings

        except Exception as e:
            print(f"Error importing data from Burp Suite: {e}")
            return []

    def _convert_from_burp_format(self, burp_issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert Burp Suite issue to API Hunter finding format.
        
        Args:
            burp_issue: Burp Suite issue data
            
        Returns:
            API Hunter finding or None if conversion fails
        """
        try:
            # Map severity levels back
            severity_map = {
                'High': 'HIGH',
                'Medium': 'MEDIUM',
                'Low': 'LOW',
                'Information': 'INFO'
            }

            finding = {
                'id': f"burp_{burp_issue.get('serial_number', 'unknown')}",
                'title': burp_issue.get('name', 'Burp Suite Finding'),
                'description': burp_issue.get('issue_background', ''),
                'severity': severity_map.get(burp_issue.get('severity', 'Low'), 'LOW'),
                'risk_level': severity_map.get(burp_issue.get('severity', 'Low'), 'LOW'),
                'affected_endpoint': f"{burp_issue.get('host', '')}{burp_issue.get('path', '')}",
                'remediation': burp_issue.get('remediation_background', ''),
                'evidence': [burp_issue.get('issue_detail', '')],
                'references': burp_issue.get('references', '').split('\n') if burp_issue.get('references') else [],
                'source': 'Burp Suite',
                'burp_issue_type': burp_issue.get('type_index'),
                'confidence': burp_issue.get('confidence', 'Tentative'),
                'discovered_at': burp_issue.get('first_seen'),
            }

            return finding

        except Exception as e:
            print(f"Error converting Burp issue to API Hunter format: {e}")
            return None

    async def sync_target_scope(self, targets: List[str]) -> bool:
        """
        Synchronize target scope with Burp Suite.
        
        Args:
            targets: List of target URLs to add to Burp Suite scope
            
        Returns:
            True if successful, False otherwise
        """
        if not self.session:
            return False

        try:
            # Add targets to Burp Suite scope
            endpoint = urljoin(self.burp_url, '/burp/target/scope')

            scope_data = {
                'include': [{'enabled': True, 'host': target} for target in targets]
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(endpoint, json=scope_data)
            )

            if response.status_code in [200, 201]:
                print(f"Successfully synchronized {len(targets)} targets with Burp Suite scope")
                return True
            else:
                print(f"Failed to sync targets with Burp Suite: {response.status_code}")
                return False

        except Exception as e:
            print(f"Error syncing targets with Burp Suite: {e}")
            return False

    async def start_active_scan(self, target_url: str) -> Optional[str]:
        """
        Start an active scan in Burp Suite.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Scan ID if successful, None otherwise
        """
        if not self.session:
            return None

        try:
            endpoint = urljoin(self.burp_url, '/burp/scanner/scans/active')

            scan_data = {
                'urls': [target_url],
                'resource_pool': 'default'
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(endpoint, json=scan_data)
            )

            if response.status_code in [200, 201]:
                scan_info = response.json()
                scan_id = scan_info.get('task_id')
                print(f"Started active scan in Burp Suite (ID: {scan_id})")
                return scan_id
            else:
                print(f"Failed to start scan in Burp Suite: {response.status_code}")
                return None

        except Exception as e:
            print(f"Error starting scan in Burp Suite: {e}")
            return None

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get status of a Burp Suite scan.
        
        Args:
            scan_id: Scan ID returned from start_active_scan
            
        Returns:
            Scan status information
        """
        if not self.session:
            return {}

        try:
            endpoint = urljoin(self.burp_url, f'/burp/scanner/scans/{scan_id}')

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.get(endpoint)
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'Failed to get scan status: {response.status_code}'}

        except Exception as e:
            return {'error': f'Error getting scan status: {e}'}

    async def generate_report(self, report_format: str = 'HTML') -> Optional[bytes]:
        """
        Generate a report from Burp Suite.
        
        Args:
            report_format: Report format (HTML, XML, etc.)
            
        Returns:
            Report data as bytes or None if failed
        """
        if not self.session:
            return None

        try:
            endpoint = urljoin(self.burp_url, '/burp/report')

            report_data = {
                'report_type': report_format,
                'include_false_positives': False,
                'issue_severity': ['High', 'Medium', 'Low']
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(endpoint, json=report_data)
            )

            if response.status_code == 200:
                print(f"Generated {report_format} report from Burp Suite")
                return response.content
            else:
                print(f"Failed to generate report from Burp Suite: {response.status_code}")
                return None

        except Exception as e:
            print(f"Error generating report from Burp Suite: {e}")
            return None
