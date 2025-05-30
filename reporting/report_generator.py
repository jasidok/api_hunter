"""
Professional report generator for API security assessments.

This module generates comprehensive reports in multiple formats including
HTML, PDF, and JSON with evidence collection and compliance mapping.
"""

import logging
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from weasyprint import HTML, CSS
except ImportError as e:
    logging.warning(f"Reporting dependencies not available: {e}")
    Environment = None
    HTML = None

from ..core.config import Config
from .evidence_collector import EvidenceCollector
from .compliance_mapper import ComplianceMapper

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats."""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    MARKDOWN = "markdown"


class ReportType(Enum):
    """Types of reports that can be generated."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILED = "technical_detailed"
    COMPLIANCE_REPORT = "compliance_report"
    VULNERABILITY_REPORT = "vulnerability_report"
    REMEDIATION_GUIDE = "remediation_guide"


@dataclass
class ReportMetadata:
    """Metadata for generated reports."""
    report_id: str
    report_type: ReportType
    format: ReportFormat
    generated_at: datetime
    target_url: str
    scan_duration: float
    total_requests: int
    vulnerabilities_found: int
    risk_score: float
    generator_version: str


@dataclass
class VulnerabilityFinding:
    """Structured vulnerability finding."""
    id: str
    title: str
    description: str
    severity: str
    risk_level: str
    cvss_score: Optional[float]
    cwe_id: Optional[str]
    owasp_category: str
    affected_endpoint: str
    request_data: Dict[str, Any]
    response_data: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    remediation: str
    references: List[str]
    discovered_at: datetime


@dataclass
class ReportSection:
    """Report section structure."""
    title: str
    content: str
    subsections: List['ReportSection']
    charts: List[Dict[str, Any]]
    tables: List[Dict[str, Any]]


class ReportGenerator:
    """Professional report generator with multiple format support."""

    def __init__(self, config: Config):
        self.config = config
        self.evidence_collector = EvidenceCollector()
        self.compliance_mapper = ComplianceMapper()

        # Report templates directory
        self.templates_dir = os.path.join(
            os.path.dirname(__file__),
            "templates"
        )

        # Initialize Jinja2 environment
        if Environment:
            self.jinja_env = Environment(
                loader=FileSystemLoader(self.templates_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.jinja_env = None

    async def generate_report(
            self,
            findings: List[VulnerabilityFinding],
            scan_data: Dict[str, Any],
            report_type: ReportType = ReportType.TECHNICAL_DETAILED,
            format: ReportFormat = ReportFormat.HTML,
            output_path: Optional[str] = None
    ) -> str:
        """
        Generate a comprehensive security report.
        
        Args:
            findings: List of vulnerability findings
            scan_data: Scan metadata and configuration
            report_type: Type of report to generate
            format: Output format
            output_path: Output file path
            
        Returns:
            Path to generated report file
        """
        # Generate report metadata
        metadata = self._generate_metadata(findings, scan_data, report_type, format)

        # Prepare report data
        report_data = await self._prepare_report_data(findings, scan_data, metadata)

        # Generate report content based on type
        if report_type == ReportType.EXECUTIVE_SUMMARY:
            content = await self._generate_executive_summary(report_data)
        elif report_type == ReportType.TECHNICAL_DETAILED:
            content = await self._generate_technical_report(report_data)
        elif report_type == ReportType.COMPLIANCE_REPORT:
            content = await self._generate_compliance_report(report_data)
        elif report_type == ReportType.VULNERABILITY_REPORT:
            content = await self._generate_vulnerability_report(report_data)
        elif report_type == ReportType.REMEDIATION_GUIDE:
            content = await self._generate_remediation_guide(report_data)
        else:
            content = await self._generate_technical_report(report_data)

        # Format and save report
        if format == ReportFormat.HTML:
            output_file = await self._generate_html_report(content, metadata, output_path)
        elif format == ReportFormat.PDF:
            output_file = await self._generate_pdf_report(content, metadata, output_path)
        elif format == ReportFormat.JSON:
            output_file = await self._generate_json_report(report_data, metadata, output_path)
        elif format == ReportFormat.MARKDOWN:
            output_file = await self._generate_markdown_report(content, metadata, output_path)
        else:
            output_file = await self._generate_html_report(content, metadata, output_path)

        logger.info(f"Generated {format.value} report: {output_file}")
        return output_file

    def _generate_metadata(
            self,
            findings: List[VulnerabilityFinding],
            scan_data: Dict[str, Any],
            report_type: ReportType,
            format: ReportFormat
    ) -> ReportMetadata:
        """Generate report metadata."""
        # Calculate risk score
        risk_score = self._calculate_risk_score(findings)

        return ReportMetadata(
            report_id=f"report_{int(datetime.now().timestamp())}",
            report_type=report_type,
            format=format,
            generated_at=datetime.now(timezone.utc),
            target_url=scan_data.get('target_url', 'Unknown'),
            scan_duration=scan_data.get('duration', 0.0),
            total_requests=scan_data.get('total_requests', 0),
            vulnerabilities_found=len(findings),
            risk_score=risk_score,
            generator_version="1.0.0"
        )

    async def _prepare_report_data(
            self,
            findings: List[VulnerabilityFinding],
            scan_data: Dict[str, Any],
            metadata: ReportMetadata
    ) -> Dict[str, Any]:
        """Prepare comprehensive report data."""
        # Categorize findings by severity
        severity_counts = self._count_by_severity(findings)

        # Get compliance mappings
        compliance_data = self.compliance_mapper.map_findings_to_frameworks(findings)

        # Generate charts data
        charts_data = self._generate_charts_data(findings, severity_counts)

        # Calculate statistics
        statistics = self._calculate_statistics(findings, scan_data)

        return {
            "metadata": asdict(metadata),
            "findings": [asdict(f) for f in findings],
            "severity_counts": severity_counts,
            "compliance_data": compliance_data,
            "charts_data": charts_data,
            "statistics": statistics,
            "scan_data": scan_data,
            "executive_summary": self._generate_executive_summary_data(findings, statistics),
            "recommendations": self._generate_recommendations(findings)
        }

    async def _generate_executive_summary(self, report_data: Dict[str, Any]) -> str:
        """Generate executive summary content."""
        summary = f"""
# Executive Summary

## Security Assessment Overview

This report presents the findings from a comprehensive API security assessment conducted on {report_data['metadata']['target_url']}.

### Key Findings

- **Total Vulnerabilities Found**: {report_data['metadata']['vulnerabilities_found']}
- **Overall Risk Score**: {report_data['metadata']['risk_score']:.1f}/10
- **Assessment Duration**: {report_data['metadata']['scan_duration']:.1f} seconds
- **Total Requests**: {report_data['metadata']['total_requests']}

### Risk Distribution

"""

        for severity, count in report_data['severity_counts'].items():
            if count > 0:
                summary += f"- **{severity.upper()}**: {count} findings\n"

        summary += f"""

### Business Impact

{self._assess_business_impact(report_data['findings'])}

### Recommended Actions

{self._generate_executive_recommendations(report_data['findings'])}
"""

        return summary

    async def _generate_technical_report(self, report_data: Dict[str, Any]) -> str:
        """Generate detailed technical report content."""
        content = f"""
# Technical Security Assessment Report

## Assessment Details

- **Target**: {report_data['metadata']['target_url']}
- **Report ID**: {report_data['metadata']['report_id']}
- **Generated**: {report_data['metadata']['generated_at']}
- **Duration**: {report_data['metadata']['scan_duration']:.2f} seconds

## Methodology

This assessment utilized automated security scanning techniques including:
- Parameter discovery and enumeration
- Input validation testing
- Authentication and authorization bypass testing
- Business logic vulnerability detection
- API-specific vulnerability testing

## Findings Summary

"""

        # Add severity breakdown
        for severity, count in report_data['severity_counts'].items():
            content += f"- {severity.upper()}: {count}\n"

        content += "\n## Detailed Findings\n\n"

        # Add detailed findings
        for finding in report_data['findings']:
            content += self._format_finding_details(finding)

        return content

    async def _generate_compliance_report(self, report_data: Dict[str, Any]) -> str:
        """Generate compliance-focused report."""
        content = f"""
# Compliance Assessment Report

## OWASP API Security Top 10 Coverage

"""

        owasp_mapping = report_data['compliance_data'].get('owasp_api_top10', {})
        for category, findings in owasp_mapping.items():
            content += f"### {category}\n"
            if findings:
                content += f"- **Findings**: {len(findings)}\n"
                content += f"- **Risk Level**: {self._assess_category_risk(findings)}\n"
            else:
                content += "- **Status**: ✓ No vulnerabilities found\n"
            content += "\n"

        return content

    async def _generate_vulnerability_report(self, report_data: Dict[str, Any]) -> str:
        """Generate vulnerability-focused report."""
        content = "# Vulnerability Report\n\n"

        # Group by severity
        by_severity = {}
        for finding in report_data['findings']:
            severity = finding['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Output by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                content += f"## {severity} Risk Vulnerabilities\n\n"
                for finding in by_severity[severity]:
                    content += self._format_finding_summary(finding)

        return content

    async def _generate_remediation_guide(self, report_data: Dict[str, Any]) -> str:
        """Generate remediation guide."""
        content = """
# Remediation Guide

## Priority Actions

Based on the identified vulnerabilities, the following actions should be prioritized:

"""

        # Sort findings by risk score
        sorted_findings = sorted(
            report_data['findings'],
            key=lambda x: self._get_severity_score(x['severity']),
            reverse=True
        )

        for i, finding in enumerate(sorted_findings[:10], 1):
            content += f"### {i}. {finding['title']}\n"
            content += f"**Risk Level**: {finding['severity']}\n"
            content += f"**Remediation**: {finding['remediation']}\n\n"

        return content

    async def _generate_html_report(
            self,
            content: str,
            metadata: ReportMetadata,
            output_path: Optional[str]
    ) -> str:
        """Generate HTML report."""
        if not self.jinja_env:
            # Fallback to basic HTML
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>API Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; }}
        .finding {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; }}
        .critical {{ border-left: 5px solid #ff0000; }}
        .high {{ border-left: 5px solid #ff6600; }}
        .medium {{ border-left: 5px solid #ffcc00; }}
        .low {{ border-left: 5px solid #00cc00; }}
    </style>
</head>
<body>
    <h1>API Security Assessment Report</h1>
    <div class="content">{content}</div>
</body>
</html>
"""
        else:
            # Use template
            template = self.jinja_env.get_template('report_template.html')
            html_content = template.render(
                content=content,
                metadata=asdict(metadata)
            )

        # Determine output path
        if not output_path:
            output_path = f"report_{metadata.report_id}.html"

        # Write file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path

    async def _generate_pdf_report(
            self,
            content: str,
            metadata: ReportMetadata,
            output_path: Optional[str]
    ) -> str:
        """Generate PDF report."""
        # First generate HTML
        html_path = await self._generate_html_report(content, metadata, None)

        # Convert to PDF if weasyprint is available
        if HTML:
            if not output_path:
                output_path = f"report_{metadata.report_id}.pdf"

            try:
                HTML(filename=html_path).write_pdf(output_path)
                # Clean up temporary HTML file
                os.unlink(html_path)
                return output_path
            except Exception as e:
                logger.error(f"PDF generation failed: {e}")
                return html_path
        else:
            logger.warning("PDF generation not available, returning HTML")
            return html_path

    async def _generate_json_report(
            self,
            report_data: Dict[str, Any],
            metadata: ReportMetadata,
            output_path: Optional[str]
    ) -> str:
        """Generate JSON report."""
        if not output_path:
            output_path = f"report_{metadata.report_id}.json"

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)

        return output_path

    async def _generate_markdown_report(
            self,
            content: str,
            metadata: ReportMetadata,
            output_path: Optional[str]
    ) -> str:
        """Generate Markdown report."""
        if not output_path:
            output_path = f"report_{metadata.report_id}.md"

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return output_path

    def _calculate_risk_score(self, findings: List[VulnerabilityFinding]) -> float:
        """Calculate overall risk score."""
        if not findings:
            return 0.0

        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 1.0
        }

        total_score = 0.0
        max_possible = len(findings) * 10.0

        for finding in findings:
            severity = finding.severity if hasattr(finding, 'severity') else finding.get('severity', 'LOW')
            total_score += severity_weights.get(severity, 1.0)

        return (total_score / max_possible) * 10.0 if max_possible > 0 else 0.0

    def _count_by_severity(self, findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for finding in findings:
            severity = finding.severity if hasattr(finding, 'severity') else finding.get('severity', 'info')
            severity_key = severity.lower()
            if severity_key in counts:
                counts[severity_key] += 1

        return counts

    def _generate_charts_data(
            self,
            findings: List[VulnerabilityFinding],
            severity_counts: Dict[str, int]
    ) -> Dict[str, Any]:
        """Generate data for charts."""
        return {
            "severity_pie": {
                "labels": list(severity_counts.keys()),
                "data": list(severity_counts.values())
            },
            "findings_timeline": self._generate_timeline_data(findings),
            "risk_matrix": self._generate_risk_matrix_data(findings)
        }

    def _generate_timeline_data(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate timeline data for findings."""
        # Simplified timeline - in full implementation would be more detailed
        return {
            "labels": ["Day 1"],
            "data": [len(findings)]
        }

    def _generate_risk_matrix_data(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate risk matrix data."""
        # Simplified risk matrix - in full implementation would be more sophisticated
        return {
            "high_probability_high_impact": len([f for f in findings if self._get_severity_score(
                f.severity if hasattr(f, 'severity') else f.get('severity', 'LOW')) >= 7]),
            "low_probability_high_impact": 0,
            "high_probability_low_impact": 0,
            "low_probability_low_impact": 0
        }

    def _calculate_statistics(self, findings: List[VulnerabilityFinding], scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate report statistics."""
        return {
            "total_findings": len(findings),
            "unique_endpoints": len(set(
                f.affected_endpoint if hasattr(f, 'affected_endpoint') else f.get('affected_endpoint', 'unknown') for f
                in findings)),
            "avg_response_time": scan_data.get('avg_response_time', 0.0),
            "success_rate": scan_data.get('success_rate', 0.0)
        }

    def _generate_executive_summary_data(self, findings: List[VulnerabilityFinding], statistics: Dict[str, Any]) -> \
    Dict[str, Any]:
        """Generate executive summary data."""
        return {
            "key_risks": [f.title if hasattr(f, 'title') else f.get('title', 'Unknown') for f in findings[:5]],
            "business_impact": self._assess_business_impact(findings),
            "recommendations": self._generate_executive_recommendations(findings)
        }

    def _generate_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        # Generic recommendations based on findings
        if any('injection' in (
        f.owasp_category if hasattr(f, 'owasp_category') else f.get('owasp_category', '')).lower() for f in findings):
            recommendations.append("Implement input validation and parameterized queries")

        if any('auth' in (f.owasp_category if hasattr(f, 'owasp_category') else f.get('owasp_category', '')).lower() for
               f in findings):
            recommendations.append("Review authentication and authorization mechanisms")

        if any('disclosure' in (f.description if hasattr(f, 'description') else f.get('description', '')).lower() for f
               in findings):
            recommendations.append("Disable debug mode and error disclosure in production")

        return recommendations

    def _format_finding_details(self, finding: Dict[str, Any]) -> str:
        """Format detailed finding information."""
        return f"""
### {finding['title']}

**Severity**: {finding['severity']}
**Risk Level**: {finding['risk_level']}
**Affected Endpoint**: {finding['affected_endpoint']}

**Description**:
{finding['description']}

**Remediation**:
{finding['remediation']}

---

"""

    def _format_finding_summary(self, finding: Dict[str, Any]) -> str:
        """Format finding summary."""
        return f"""
#### {finding['title']}
- **Severity**: {finding['severity']}
- **Endpoint**: {finding['affected_endpoint']}
- **Description**: {finding['description'][:200]}...

"""

    def _assess_business_impact(self, findings: List[Any]) -> str:
        """Assess business impact of findings."""
        critical_count = len(
            [f for f in findings if (f.severity if hasattr(f, 'severity') else f.get('severity', 'LOW')) == 'CRITICAL'])
        high_count = len(
            [f for f in findings if (f.severity if hasattr(f, 'severity') else f.get('severity', 'LOW')) == 'HIGH'])

        if critical_count > 0:
            return "CRITICAL: Immediate action required. Risk of data breach or system compromise."
        elif high_count > 0:
            return "HIGH: Significant security risks identified. Remediation should be prioritized."
        else:
            return "MODERATE: Some security issues found but overall risk is manageable."

    def _generate_executive_recommendations(self, findings: List[Any]) -> str:
        """Generate executive-level recommendations."""
        recommendations = []

        severity_counts = self._count_by_severity(findings)

        if severity_counts['critical'] > 0 or severity_counts['high'] > 0:
            recommendations.append("Implement emergency security patches for critical vulnerabilities")
            recommendations.append("Conduct security training for development team")

        recommendations.append("Establish regular security testing schedule")
        recommendations.append("Implement secure coding guidelines")

        return "\n".join(f"- {rec}" for rec in recommendations)

    def _assess_category_risk(self, findings: List[Any]) -> str:
        """Assess risk level for a category."""
        if not findings:
            return "LOW"

        max_severity = max(self._get_severity_score(f.get('severity', 'LOW')) for f in findings)

        if max_severity >= 9:
            return "CRITICAL"
        elif max_severity >= 7:
            return "HIGH"
        elif max_severity >= 5:
            return "MEDIUM"
        else:
            return "LOW"

    def _get_severity_score(self, severity: str) -> float:
        """Get numeric score for severity."""
        scores = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 1.0
        }
        return scores.get(severity.upper(), 1.0)
