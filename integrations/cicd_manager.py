"""
CI/CD Integration Manager

Manages integrations with various CI/CD platforms for automated security testing.
"""

import json
import asyncio
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


class CICDPlatform(Enum):
    """Supported CI/CD platforms."""
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_DEVOPS = "azure_devops"
    CIRCLECI = "circleci"
    TRAVIS_CI = "travis_ci"


@dataclass
class ScanConfiguration:
    """Configuration for automated scans in CI/CD."""
    target_urls: List[str]
    scan_types: List[str] = None
    severity_threshold: str = "MEDIUM"
    fail_on_vulnerabilities: bool = True
    report_formats: List[str] = None
    notification_channels: List[str] = None
    max_scan_duration: int = 600  # seconds
    parallel_scans: bool = True

    def __post_init__(self):
        if self.scan_types is None:
            self.scan_types = ["discovery", "vulnerabilities"]
        if self.report_formats is None:
            self.report_formats = ["json", "html"]
        if self.notification_channels is None:
            self.notification_channels = []


@dataclass
class PipelineResult:
    """Result of a CI/CD pipeline scan."""
    success: bool
    scan_id: str
    vulnerabilities_found: int
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int
    scan_duration: float
    report_paths: List[str]
    error_message: Optional[str] = None
    exit_code: int = 0


class CICDManager:
    """
    Manages CI/CD pipeline integrations for automated security testing.
    
    Features:
    - Generate pipeline configuration files
    - Execute scans within CI/CD environments
    - Handle environment variable configuration
    - Process scan results and generate appropriate exit codes
    - Generate security reports for pipeline artifacts
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the CI/CD manager.
        
        Args:
            config: Configuration including platform settings
        """
        self.config = config or {}
        self.platform_integrations = {}

    async def initialize(self) -> None:
        """Initialize CI/CD integrations."""
        # Initialize platform-specific integrations
        for platform in CICDPlatform:
            try:
                integration = self._create_platform_integration(platform)
                if integration:
                    self.platform_integrations[platform] = integration
            except Exception as e:
                print(f"Failed to initialize {platform.value} integration: {e}")

    def _create_platform_integration(self, platform: CICDPlatform):
        """Create platform-specific integration instance."""
        # This would be implemented with actual platform integrations
        # For now, return a placeholder
        return None

    def detect_cicd_environment(self) -> Optional[CICDPlatform]:
        """
        Detect the current CI/CD platform from environment variables.
        
        Returns:
            Detected platform or None if not in CI/CD environment
        """
        import os

        # GitHub Actions
        if os.getenv('GITHUB_ACTIONS'):
            return CICDPlatform.GITHUB_ACTIONS

        # GitLab CI
        if os.getenv('GITLAB_CI'):
            return CICDPlatform.GITLAB_CI

        # Jenkins
        if os.getenv('JENKINS_URL') or os.getenv('BUILD_NUMBER'):
            return CICDPlatform.JENKINS

        # Azure DevOps
        if os.getenv('AZURE_HTTP_USER_AGENT'):
            return CICDPlatform.AZURE_DEVOPS

        # CircleCI
        if os.getenv('CIRCLECI'):
            return CICDPlatform.CIRCLECI

        # Travis CI
        if os.getenv('TRAVIS'):
            return CICDPlatform.TRAVIS_CI

        return None

    def generate_pipeline_config(self, platform: CICDPlatform,
                                 scan_config: ScanConfiguration,
                                 output_path: Optional[str] = None) -> str:
        """
        Generate pipeline configuration file for the specified platform.
        
        Args:
            platform: Target CI/CD platform
            scan_config: Scan configuration
            output_path: Optional output path for the config file
            
        Returns:
            Generated configuration content
        """
        if platform == CICDPlatform.GITHUB_ACTIONS:
            config_content = self._generate_github_actions_config(scan_config)
            filename = '.github/workflows/api-security-scan.yml'
        elif platform == CICDPlatform.GITLAB_CI:
            config_content = self._generate_gitlab_ci_config(scan_config)
            filename = '.gitlab-ci.yml'
        elif platform == CICDPlatform.JENKINS:
            config_content = self._generate_jenkins_config(scan_config)
            filename = 'Jenkinsfile'
        else:
            raise ValueError(f"Unsupported platform: {platform}")

        # Write to file if output path specified
        if output_path:
            config_path = Path(output_path) / filename
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(config_content)
            print(f"Generated {platform.value} configuration: {config_path}")

        return config_content

    def _generate_github_actions_config(self, scan_config: ScanConfiguration) -> str:
        """Generate GitHub Actions workflow configuration."""
        targets = " ".join(scan_config.target_urls)
        scan_types = ",".join(scan_config.scan_types)
        report_formats = ",".join(scan_config.report_formats)

        config = f"""name: API Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  api-security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
        
    - name: Install API Hunter
      run: |
        pip install api-hunter
        
    - name: Run API Security Scan
      env:
        API_HUNTER_TARGETS: "{targets}"
        API_HUNTER_SCAN_TYPES: "{scan_types}"
        API_HUNTER_SEVERITY_THRESHOLD: "{scan_config.severity_threshold}"
        API_HUNTER_FAIL_ON_VULNS: "{scan_config.fail_on_vulnerabilities}"
        API_HUNTER_REPORT_FORMATS: "{report_formats}"
        API_HUNTER_MAX_DURATION: "{scan_config.max_scan_duration}"
      run: |
        api-hunter cicd-scan \\
          --targets "${{{{ env.API_HUNTER_TARGETS }}}}" \\
          --scan-types "${{{{ env.API_HUNTER_SCAN_TYPES }}}}" \\
          --severity-threshold "${{{{ env.API_HUNTER_SEVERITY_THRESHOLD }}}}" \\
          --report-formats "${{{{ env.API_HUNTER_REPORT_FORMATS }}}}" \\
          --output-dir "./security-reports" \\
          --fail-on-vulns="${{{{ scan_config.fail_on_vulnerabilities and 'true' or 'false' }}}}"
          
    - name: Upload Security Reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: api-security-reports
        path: ./security-reports/
        
    - name: Comment PR with Results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const path = './security-reports/summary.json';
          
          if (fs.existsSync(path)) {{
            const summary = JSON.parse(fs.readFileSync(path, 'utf8'));
            
            const comment = `## 🛡️ API Security Scan Results
            
**Target URLs:** {targets}
**Vulnerabilities Found:** ${{summary.total_vulnerabilities || 0}}
**High Severity:** ${{summary.high_severity || 0}}
**Medium Severity:** ${{summary.medium_severity || 0}}
**Low Severity:** ${{summary.low_severity || 0}}

${{summary.total_vulnerabilities > 0 ? '⚠️ Security issues detected. Please review the full report.' : '✅ No security issues detected.'}}

[View Full Report](../actions/runs/${{{{ github.run_id }}}})
            `;
            
            github.rest.issues.createComment({{
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            }});
          }}
"""

        return config

    def _generate_gitlab_ci_config(self, scan_config: ScanConfiguration) -> str:
        """Generate GitLab CI configuration."""
        targets = " ".join(scan_config.target_urls)
        scan_types = ",".join(scan_config.scan_types)
        report_formats = ",".join(scan_config.report_formats)

        config = f"""stages:
  - security-scan

variables:
  API_HUNTER_TARGETS: "{targets}"
  API_HUNTER_SCAN_TYPES: "{scan_types}"
  API_HUNTER_SEVERITY_THRESHOLD: "{scan_config.severity_threshold}"
  API_HUNTER_FAIL_ON_VULNS: "{scan_config.fail_on_vulnerabilities}"
  API_HUNTER_REPORT_FORMATS: "{report_formats}"
  API_HUNTER_MAX_DURATION: "{scan_config.max_scan_duration}"

api-security-scan:
  stage: security-scan
  image: python:3.11-slim
  
  before_script:
    - pip install api-hunter
    
  script:
    - |
      api-hunter cicd-scan \\
        --targets "$API_HUNTER_TARGETS" \\
        --scan-types "$API_HUNTER_SCAN_TYPES" \\
        --severity-threshold "$API_HUNTER_SEVERITY_THRESHOLD" \\
        --report-formats "$API_HUNTER_REPORT_FORMATS" \\
        --output-dir "./security-reports" \\
        --fail-on-vulns=$API_HUNTER_FAIL_ON_VULNS
        
  artifacts:
    reports:
      junit: security-reports/junit-report.xml
    paths:
      - security-reports/
    expire_in: 30 days
    when: always
    
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "schedule"
"""

        return config

    def _generate_jenkins_config(self, scan_config: ScanConfiguration) -> str:
        """Generate Jenkins pipeline configuration."""
        targets = " ".join(scan_config.target_urls)
        scan_types = ",".join(scan_config.scan_types)
        report_formats = ",".join(scan_config.report_formats)

        config = f"""pipeline {{
    agent any
    
    environment {{
        API_HUNTER_TARGETS = "{targets}"
        API_HUNTER_SCAN_TYPES = "{scan_types}"
        API_HUNTER_SEVERITY_THRESHOLD = "{scan_config.severity_threshold}"
        API_HUNTER_FAIL_ON_VULNS = "{scan_config.fail_on_vulnerabilities}"
        API_HUNTER_REPORT_FORMATS = "{report_formats}"
        API_HUNTER_MAX_DURATION = "{scan_config.max_scan_duration}"
    }}
    
    stages {{
        stage('Setup') {{
            steps {{
                sh 'pip install api-hunter'
            }}
        }}
        
        stage('API Security Scan') {{
            steps {{
                sh '''
                    api-hunter cicd-scan \\
                        --targets "$API_HUNTER_TARGETS" \\
                        --scan-types "$API_HUNTER_SCAN_TYPES" \\
                        --severity-threshold "$API_HUNTER_SEVERITY_THRESHOLD" \\
                        --report-formats "$API_HUNTER_REPORT_FORMATS" \\
                        --output-dir "./security-reports" \\
                        --fail-on-vulns=$API_HUNTER_FAIL_ON_VULNS
                '''
            }}
            
            post {{
                always {{
                    archiveArtifacts artifacts: 'security-reports/**/*', allowEmptyArchive: true
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'security-reports',
                        reportFiles: 'report.html',
                        reportName: 'API Security Report'
                    ])
                }}
            }}
        }}
    }}
    
    post {{
        failure {{
            emailext (
                subject: "API Security Scan Failed - Build #${{BUILD_NUMBER}}",
                body: "The API security scan has failed. Please check the build logs and security report.",
                to: "${{DEFAULT_RECIPIENTS}}"
            )
        }}
        
        success {{
            script {{
                def summary = readJSON file: 'security-reports/summary.json'
                if (summary.total_vulnerabilities > 0) {{
                    emailext (
                        subject: "Security Vulnerabilities Detected - Build #${{BUILD_NUMBER}}",
                        body: "API security scan found ${{summary.total_vulnerabilities}} vulnerabilities. Please review the security report.",
                        to: "${{DEFAULT_RECIPIENTS}}"
                    )
                }}
            }}
        }}
    }}
}}"""

        return config

    async def execute_cicd_scan(self,
                                targets: List[str],
                                scan_types: List[str] = None,
                                severity_threshold: str = "MEDIUM",
                                fail_on_vulnerabilities: bool = True,
                                report_formats: List[str] = None,
                                output_dir: str = "./security-reports",
                                max_duration: int = 600) -> PipelineResult:
        """
        Execute a security scan within a CI/CD environment.
        
        Args:
            targets: List of target URLs to scan
            scan_types: Types of scans to perform
            severity_threshold: Minimum severity to report
            fail_on_vulnerabilities: Whether to fail pipeline on vulnerabilities
            report_formats: Output report formats
            output_dir: Directory for scan reports
            max_duration: Maximum scan duration in seconds
            
        Returns:
            Pipeline result with scan status and metrics
        """
        scan_id = f"cicd_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()

        try:
            # Import here to avoid circular imports
            from ..main import scan_and_report

            # Set default values
            if scan_types is None:
                scan_types = ["discovery", "vulnerabilities"]
            if report_formats is None:
                report_formats = ["json", "html"]

            # Create output directory
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Execute scans for each target
            all_findings = []
            report_paths = []

            for target in targets:
                print(f"Scanning target: {target}")

                # Run the scan (simplified - would use actual scan_and_report function)
                # This is a placeholder for the actual implementation
                scan_result = await self._mock_scan_execution(target, scan_types)
                all_findings.extend(scan_result.get('findings', []))

                # Generate reports
                for format_type in report_formats:
                    report_filename = f"{target.replace('://', '_').replace('/', '_')}_{scan_id}.{format_type}"
                    report_path = output_path / report_filename
                    report_paths.append(str(report_path))

                    # Generate report (placeholder)
                    await self._generate_report(scan_result, report_path, format_type)

            # Calculate metrics
            severity_counts = self._count_vulnerabilities_by_severity(all_findings)
            total_vulnerabilities = len(all_findings)
            high_severity = severity_counts.get('HIGH', 0) + severity_counts.get('CRITICAL', 0)

            # Generate summary report
            summary_data = {
                'scan_id': scan_id,
                'targets': targets,
                'scan_types': scan_types,
                'total_vulnerabilities': total_vulnerabilities,
                'high_severity': high_severity,
                'medium_severity': severity_counts.get('MEDIUM', 0),
                'low_severity': severity_counts.get('LOW', 0),
                'scan_duration': (datetime.now() - start_time).total_seconds(),
                'timestamp': datetime.now().isoformat()
            }

            summary_path = output_path / 'summary.json'
            summary_path.write_text(json.dumps(summary_data, indent=2))

            # Determine success/failure
            should_fail = False
            if fail_on_vulnerabilities:
                threshold_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
                threshold_value = threshold_levels.get(severity_threshold, 2)

                for severity, count in severity_counts.items():
                    if count > 0 and threshold_levels.get(severity, 0) >= threshold_value:
                        should_fail = True
                        break

            scan_duration = (datetime.now() - start_time).total_seconds()

            return PipelineResult(
                success=not should_fail,
                scan_id=scan_id,
                vulnerabilities_found=total_vulnerabilities,
                high_severity_count=high_severity,
                medium_severity_count=severity_counts.get('MEDIUM', 0),
                low_severity_count=severity_counts.get('LOW', 0),
                scan_duration=scan_duration,
                report_paths=report_paths,
                exit_code=1 if should_fail else 0
            )

        except Exception as e:
            scan_duration = (datetime.now() - start_time).total_seconds()

            return PipelineResult(
                success=False,
                scan_id=scan_id,
                vulnerabilities_found=0,
                high_severity_count=0,
                medium_severity_count=0,
                low_severity_count=0,
                scan_duration=scan_duration,
                report_paths=[],
                error_message=str(e),
                exit_code=2
            )

    async def _mock_scan_execution(self, target: str, scan_types: List[str]) -> Dict[str, Any]:
        """Mock scan execution for testing purposes."""
        # This would be replaced with actual scan execution
        return {
            'target': target,
            'scan_types': scan_types,
            'findings': [
                {
                    'title': 'Example Vulnerability',
                    'severity': 'MEDIUM',
                    'description': 'This is a mock vulnerability for testing'
                }
            ]
        }

    async def _generate_report(self, scan_result: Dict[str, Any],
                               report_path: Path, format_type: str) -> None:
        """Generate a scan report in the specified format."""
        if format_type == 'json':
            report_path.write_text(json.dumps(scan_result, indent=2))
        elif format_type == 'html':
            # Generate simple HTML report
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>API Security Scan Report</title>
</head>
<body>
    <h1>API Security Scan Report</h1>
    <h2>Target: {scan_result.get('target', 'Unknown')}</h2>
    <h3>Findings: {len(scan_result.get('findings', []))}</h3>
    <pre>{json.dumps(scan_result, indent=2)}</pre>
</body>
</html>
            """
            report_path.write_text(html_content)

    def _count_vulnerabilities_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {}
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def get_environment_config(self) -> Dict[str, Any]:
        """
        Get CI/CD environment configuration from environment variables.
        
        Returns:
            Configuration dictionary extracted from environment
        """
        import os

        config = {}

        # Extract API Hunter specific environment variables
        env_vars = {
            'API_HUNTER_TARGETS': 'targets',
            'API_HUNTER_SCAN_TYPES': 'scan_types',
            'API_HUNTER_SEVERITY_THRESHOLD': 'severity_threshold',
            'API_HUNTER_FAIL_ON_VULNS': 'fail_on_vulnerabilities',
            'API_HUNTER_REPORT_FORMATS': 'report_formats',
            'API_HUNTER_MAX_DURATION': 'max_duration',
            'API_HUNTER_OUTPUT_DIR': 'output_dir',
            'API_HUNTER_PARALLEL_SCANS': 'parallel_scans'
        }

        for env_var, config_key in env_vars.items():
            value = os.getenv(env_var)
            if value:
                # Parse different value types
                if config_key in ['fail_on_vulnerabilities', 'parallel_scans']:
                    config[config_key] = value.lower() in ['true', '1', 'yes']
                elif config_key in ['max_duration']:
                    config[config_key] = int(value)
                elif config_key in ['targets', 'scan_types', 'report_formats']:
                    config[config_key] = [item.strip() for item in value.split(',')]
                else:
                    config[config_key] = value

        return config
