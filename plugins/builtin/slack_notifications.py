"""
Slack Notifications Plugin

Provides integration with Slack for sending notifications and reports.
"""

import json
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp

from ..base_plugin import NotificationPlugin, PluginInfo, PluginType


class SlackNotificationPlugin(NotificationPlugin):
    """
    Slack notification plugin for API Hunter.
    
    Features:
    - Send real-time scan notifications
    - Send vulnerability alerts with severity-based formatting
    - Send comprehensive scan reports
    - Support multiple channels and webhooks
    - Custom message formatting and templates
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Slack notification plugin.
        
        Args:
            config: Plugin configuration including Slack webhook URLs and settings
        """
        super().__init__(config)
        self.webhook_url = self.config.get('webhook_url', '')
        self.channels = self.config.get('channels', {})
        self.mention_users = self.config.get('mention_users', {})
        self.severity_colors = {
            'CRITICAL': '#ff0000',  # Red
            'HIGH': '#ff8c00',  # Orange
            'MEDIUM': '#ffd700',  # Gold
            'LOW': '#00ff00',  # Green
            'INFO': '#87ceeb'  # Sky Blue
        }

    @property
    def plugin_info(self) -> PluginInfo:
        """Return plugin metadata."""
        return PluginInfo(
            name="slack_notifications",
            version="1.0.0",
            description="Slack integration for sending notifications and scan reports",
            author="API Hunter Team",
            plugin_type=PluginType.NOTIFICATION,
            dependencies=["aiohttp"],
            config_schema={
                "required": ["webhook_url"],
                "optional": ["channels", "mention_users", "template_overrides"],
                "properties": {
                    "webhook_url": {"type": "string", "description": "Primary Slack webhook URL"},
                    "channels": {"type": "object", "description": "Named webhook URLs for different channels"},
                    "mention_users": {"type": "object",
                                      "description": "User IDs to mention for different severity levels"},
                    "template_overrides": {"type": "object", "description": "Custom message templates"}
                }
            }
        )

    async def initialize(self) -> bool:
        """Initialize the plugin and test Slack connectivity."""
        try:
            if not self.webhook_url:
                print("Slack webhook URL not configured")
                return False

            # Test the webhook with a simple message
            success = await self._test_webhook()
            if success:
                print("Slack notification plugin initialized successfully")
            else:
                print("Failed to initialize Slack notifications - webhook test failed")

            return success

        except Exception as e:
            print(f"Failed to initialize Slack notifications: {e}")
            return False

    async def cleanup(self) -> None:
        """Clean up plugin resources."""
        # Nothing specific to clean up for Slack notifications
        pass

    async def _test_webhook(self) -> bool:
        """Test the Slack webhook connectivity."""
        try:
            test_message = {
                "text": "🔧 API Hunter Slack integration test - plugin initialized successfully",
                "username": "API Hunter",
                "icon_emoji": ":shield:"
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=test_message) as response:
                    return response.status == 200

        except Exception as e:
            print(f"Slack webhook test failed: {e}")
            return False

    async def send_notification(self, message: str, severity: str = "info") -> bool:
        """
        Send a notification to Slack.
        
        Args:
            message: Notification message
            severity: Message severity (info, warning, error, critical)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Map severity to Slack format
            severity_upper = severity.upper()

            # Choose appropriate emoji and color
            emoji_map = {
                'CRITICAL': ':red_circle:',
                'HIGH': ':orange_circle:',
                'MEDIUM': ':yellow_circle:',
                'LOW': ':green_circle:',
                'INFO': ':information_source:',
                'WARNING': ':warning:',
                'ERROR': ':x:'
            }

            emoji = emoji_map.get(severity_upper, ':information_source:')
            color = self.severity_colors.get(severity_upper, '#87ceeb')

            # Build Slack message
            slack_message = {
                "username": "API Hunter",
                "icon_emoji": ":shield:",
                "attachments": [{
                    "color": color,
                    "fields": [{
                        "title": f"{emoji} API Hunter Notification",
                        "value": message,
                        "short": False
                    }],
                    "footer": "API Hunter Security Scanner",
                    "ts": int(datetime.now().timestamp())
                }]
            }

            # Add mentions for high-severity notifications
            if severity_upper in ['CRITICAL', 'HIGH'] and self.mention_users.get(severity_upper):
                users = self.mention_users[severity_upper]
                if isinstance(users, str):
                    users = [users]
                mentions = ' '.join([f"<@{user}>" for user in users])
                slack_message["text"] = f"{mentions} High severity notification:"

            # Send to primary webhook
            success = await self._send_to_webhook(self.webhook_url, slack_message)

            # Send to specific severity channel if configured
            severity_channel = self.channels.get(severity_upper)
            if severity_channel and severity_channel != self.webhook_url:
                await self._send_to_webhook(severity_channel, slack_message)

            return success

        except Exception as e:
            print(f"Error sending Slack notification: {e}")
            return False

    async def send_report(self, report_data: Dict[str, Any]) -> bool:
        """
        Send a comprehensive scan report to Slack.
        
        Args:
            report_data: Scan report data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Extract key information from report
            target_url = report_data.get('target_url', 'Unknown')
            findings = report_data.get('findings', [])
            scan_duration = report_data.get('duration', 0)
            total_requests = report_data.get('total_requests', 0)

            # Count vulnerabilities by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'LOW')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Calculate risk score
            risk_score = self._calculate_risk_score(severity_counts)

            # Choose color based on highest severity found
            report_color = self._get_report_color(severity_counts)

            # Build comprehensive report message
            report_message = {
                "username": "API Hunter",
                "icon_emoji": ":shield:",
                "attachments": [{
                    "color": report_color,
                    "title": f"🛡️ API Security Scan Complete: {target_url}",
                    "fields": [
                        {
                            "title": "Target",
                            "value": target_url,
                            "short": True
                        },
                        {
                            "title": "Duration",
                            "value": f"{scan_duration:.2f} seconds",
                            "short": True
                        },
                        {
                            "title": "Total Requests",
                            "value": str(total_requests),
                            "short": True
                        },
                        {
                            "title": "Vulnerabilities Found",
                            "value": str(len(findings)),
                            "short": True
                        },
                        {
                            "title": "Risk Score",
                            "value": f"{risk_score}/100",
                            "short": True
                        }
                    ],
                    "footer": "API Hunter Security Scanner",
                    "ts": int(datetime.now().timestamp())
                }]
            }

            # Add severity breakdown if vulnerabilities found
            if findings:
                severity_breakdown = self._format_severity_breakdown(severity_counts)
                report_message["attachments"][0]["fields"].append({
                    "title": "Severity Breakdown",
                    "value": severity_breakdown,
                    "short": False
                })

                # Add top vulnerabilities
                top_vulns = self._get_top_vulnerabilities(findings)
                if top_vulns:
                    report_message["attachments"][0]["fields"].append({
                        "title": "Top Vulnerabilities",
                        "value": top_vulns,
                        "short": False
                    })

            # Add mentions for high-risk scans
            if risk_score >= 70 and self.mention_users.get('HIGH'):
                users = self.mention_users['HIGH']
                if isinstance(users, str):
                    users = [users]
                mentions = ' '.join([f"<@{user}>" for user in users])
                report_message["text"] = f"{mentions} High-risk scan results:"

            # Send to reports channel if configured
            reports_webhook = self.channels.get('reports', self.webhook_url)
            success = await self._send_to_webhook(reports_webhook, report_message)

            # Send summary to main channel
            if reports_webhook != self.webhook_url:
                summary_message = self._create_summary_message(report_data, risk_score)
                await self._send_to_webhook(self.webhook_url, summary_message)

            return success

        except Exception as e:
            print(f"Error sending Slack report: {e}")
            return False

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """
        Calculate a risk score based on vulnerability severities.
        
        Args:
            severity_counts: Dictionary of severity levels and their counts
            
        Returns:
            Risk score from 0-100
        """
        # Scoring weights
        weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 8,
            'LOW': 3,
            'INFO': 1
        }

        total_score = 0
        for severity, count in severity_counts.items():
            weight = weights.get(severity, 0)
            total_score += weight * count

        # Cap at 100
        return min(total_score, 100)

    def _get_report_color(self, severity_counts: Dict[str, int]) -> str:
        """Get report color based on highest severity found."""
        if severity_counts.get('CRITICAL', 0) > 0:
            return self.severity_colors['CRITICAL']
        elif severity_counts.get('HIGH', 0) > 0:
            return self.severity_colors['HIGH']
        elif severity_counts.get('MEDIUM', 0) > 0:
            return self.severity_colors['MEDIUM']
        elif severity_counts.get('LOW', 0) > 0:
            return self.severity_colors['LOW']
        else:
            return self.severity_colors['INFO']

    def _format_severity_breakdown(self, severity_counts: Dict[str, int]) -> str:
        """Format severity breakdown for Slack message."""
        if not severity_counts:
            return "No vulnerabilities found"

        breakdown = []
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {
                    'CRITICAL': ':red_circle:',
                    'HIGH': ':orange_circle:',
                    'MEDIUM': ':yellow_circle:',
                    'LOW': ':green_circle:',
                    'INFO': ':information_source:'
                }.get(severity, ':question:')
                breakdown.append(f"{emoji} {severity}: {count}")

        return '\n'.join(breakdown)

    def _get_top_vulnerabilities(self, findings: List[Dict[str, Any]], limit: int = 5) -> str:
        """Get top vulnerabilities for the report."""
        if not findings:
            return "No vulnerabilities found"

        # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get('severity', 'INFO'), 4)
        )

        top_vulns = []
        for i, finding in enumerate(sorted_findings[:limit], 1):
            severity = finding.get('severity', 'LOW')
            title = finding.get('title', 'Unknown Vulnerability')
            endpoint = finding.get('affected_endpoint', '')

            # Truncate long titles
            if len(title) > 50:
                title = title[:47] + "..."

            # Truncate long endpoints
            if len(endpoint) > 40:
                endpoint = endpoint[:37] + "..."

            emoji = {
                'CRITICAL': ':red_circle:',
                'HIGH': ':orange_circle:',
                'MEDIUM': ':yellow_circle:',
                'LOW': ':green_circle:',
                'INFO': ':information_source:'
            }.get(severity, ':question:')

            top_vulns.append(f"{i}. {emoji} {title}")
            if endpoint:
                top_vulns.append(f"   📍 {endpoint}")

        return '\n'.join(top_vulns)

    def _create_summary_message(self, report_data: Dict[str, Any], risk_score: int) -> Dict[str, Any]:
        """Create a summary message for the main channel."""
        target_url = report_data.get('target_url', 'Unknown')
        findings_count = len(report_data.get('findings', []))

        summary_text = f"🛡️ Scan completed for `{target_url}`\n"
        summary_text += f"📊 Found {findings_count} issues (Risk Score: {risk_score}/100)"

        color = "#00ff00"  # Green
        if risk_score >= 70:
            color = "#ff0000"  # Red
        elif risk_score >= 40:
            color = "#ffd700"  # Gold
        elif risk_score >= 20:
            color = "#ffa500"  # Orange

        return {
            "username": "API Hunter",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color,
                "text": summary_text,
                "footer": "API Hunter Security Scanner",
                "ts": int(datetime.now().timestamp())
            }]
        }

    async def _send_to_webhook(self, webhook_url: str, message: Dict[str, Any]) -> bool:
        """
        Send a message to a specific Slack webhook.
        
        Args:
            webhook_url: Slack webhook URL
            message: Slack message payload
            
        Returns:
            True if successful, False otherwise
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=message) as response:
                    if response.status == 200:
                        return True
                    else:
                        print(f"Slack webhook returned status {response.status}")
                        return False

        except Exception as e:
            print(f"Error sending message to Slack webhook: {e}")
            return False

    async def send_scan_started_notification(self, target_url: str, scan_type: str) -> bool:
        """
        Send notification when a scan starts.
        
        Args:
            target_url: Target URL being scanned
            scan_type: Type of scan being performed
            
        Returns:
            True if successful, False otherwise
        """
        message = f"🚀 Started {scan_type} scan for `{target_url}`"
        return await self.send_notification(message, "info")

    async def send_vulnerability_alert(self, finding: Dict[str, Any]) -> bool:
        """
        Send immediate alert for high-severity vulnerabilities.
        
        Args:
            finding: Vulnerability finding data
            
        Returns:
            True if successful, False otherwise
        """
        severity = finding.get('severity', 'LOW')

        # Only send alerts for HIGH and CRITICAL vulnerabilities
        if severity not in ['HIGH', 'CRITICAL']:
            return True

        title = finding.get('title', 'Unknown Vulnerability')
        endpoint = finding.get('affected_endpoint', '')
        description = finding.get('description', '')

        # Truncate description for alert
        if len(description) > 200:
            description = description[:197] + "..."

        alert_message = f"🚨 {severity} severity vulnerability detected!\n\n"
        alert_message += f"**{title}**\n"
        alert_message += f"📍 Endpoint: `{endpoint}`\n"
        alert_message += f"📝 {description}"

        return await self.send_notification(alert_message, severity.lower())

    async def send_scan_error_notification(self, target_url: str, error_message: str) -> bool:
        """
        Send notification when a scan encounters an error.
        
        Args:
            target_url: Target URL that failed
            error_message: Error message
            
        Returns:
            True if successful, False otherwise
        """
        message = f"❌ Scan failed for `{target_url}`\n"
        message += f"Error: {error_message}"
        return await self.send_notification(message, "error")

    async def send_custom_message(self, title: str, message: str,
                                  color: str = "#36a64f", channel: str = None) -> bool:
        """
        Send a custom formatted message to Slack.
        
        Args:
            title: Message title
            message: Message content
            color: Message color (hex)
            channel: Specific channel key from config
            
        Returns:
            True if successful, False otherwise
        """
        try:
            slack_message = {
                "username": "API Hunter",
                "icon_emoji": ":shield:",
                "attachments": [{
                    "color": color,
                    "title": title,
                    "text": message,
                    "footer": "API Hunter Security Scanner",
                    "ts": int(datetime.now().timestamp())
                }]
            }

            # Use specific channel or default webhook
            webhook_url = self.channels.get(channel, self.webhook_url) if channel else self.webhook_url

            return await self._send_to_webhook(webhook_url, slack_message)

        except Exception as e:
            print(f"Error sending custom Slack message: {e}")
            return False
