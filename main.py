#!/usr/bin/env python3
"""
API Hunter - Advanced Bug Bounty Tool for API Security Testing

Main CLI entry point for the application.
"""

import sys
import asyncio
import json
from pathlib import Path
from typing import List, Optional
from datetime import datetime

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from api_hunter import __version__
from api_hunter.core.config import get_config, Config
from api_hunter.core.logger import configure_logging, get_logger

console = Console()
logger = get_logger()


@click.group()
@click.version_option(version=__version__)
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--config-file', type=click.Path(exists=True), help='Path to configuration file')
@click.option('--log-level',
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']),
              default='INFO', help='Set logging level')
@click.option('--log-file', type=click.Path(), help='Path to log file')
@click.pass_context
def cli(ctx, debug, config_file, log_level, log_file):
    """API Hunter - Advanced Bug Bounty Tool for API Security Testing"""

    # Ensure context object exists
    ctx.ensure_object(dict)

    # Store global options
    ctx.obj['debug'] = debug
    ctx.obj['config_file'] = config_file
    ctx.obj['log_level'] = log_level
    ctx.obj['log_file'] = log_file

    # Configure logging
    log_path = Path(log_file) if log_file else None
    configure_logging(
        level=log_level if not debug else 'DEBUG',
        log_file=log_path,
        rich_console=True,
        show_time=debug,
        show_path=debug
    )

    # Load configuration
    config = get_config()
    if debug:
        config.debug = True
        config.log_level = 'DEBUG'

    # Display banner
    if not ctx.obj.get('quiet', False):
        display_banner()


def display_banner():
    """Display the API Hunter banner."""
    banner = f"""
[bold cyan]API Hunter[/bold cyan] v{__version__}
[dim]Advanced Bug Bounty Tool for API Security Testing[/dim]

[yellow]⚠️  Use responsibly and only on systems you own or have permission to test[/yellow]
"""
    console.print(Panel(banner, title="Welcome", border_style="blue"))


@cli.command()
@click.argument('url')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', 'report_format',
              type=click.Choice(['html', 'pdf', 'json', 'markdown']),
              default='html', help='Report format')
@click.option('--type', 'report_type',
              type=click.Choice(['executive', 'technical', 'compliance', 'vulnerability', 'remediation']),
              default='technical', help='Report type')
@click.option('--include-ai-analysis', is_flag=True, help='Include AI-powered analysis')
@click.option('--max-requests', default=100, help='Maximum requests for scanning')
async def scan_and_report(url, output, report_format, report_type, include_ai_analysis, max_requests):
    """Perform comprehensive scan and generate professional report."""
    console.print(f"[bold blue]Starting comprehensive scan of {url}[/bold blue]")

    # Load configuration
    config = get_config()
    configure_logging(config.log_level if hasattr(config, 'log_level') else 'INFO')

    # Initialize components
    from api_hunter.core.http_client import HTTPClient
    from api_hunter.core.ai_analyzer import AIResponseAnalyzer, VulnerabilityChainer, AnalysisType
    from api_hunter.discovery.openapi_discoverer import OpenAPIDiscoverer
    from api_hunter.discovery.rest_discoverer import RESTDiscoverer
    from api_hunter.discovery.technology_fingerprinter import TechnologyFingerprinter
    from api_hunter.vulnerabilities.bola_detector import BOLADetector
    from api_hunter.vulnerabilities.bfla_detector import BFLADetector
    from api_hunter.vulnerabilities.mass_assignment import MassAssignmentDetector
    from api_hunter.vulnerabilities.injection_tester import InjectionTester
    from api_hunter.vulnerabilities.ssrf_detector import SSRFDetector
    from api_hunter.vulnerabilities.business_logic import BusinessLogicDetector
    from api_hunter.fuzzing.fuzzer_engine import FuzzerEngine, FuzzingStrategy
    from api_hunter.reporting.report_generator import ReportGenerator, ReportType, ReportFormat

    http_client = HTTPClient(config)

    scan_results = {
        'target_url': url,
        'start_time': datetime.now(),
        'findings': [],
        'total_requests': 0,
        'duration': 0.0
    }

    try:
        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
        ) as progress:

            # Discovery phase
            discovery_task = progress.add_task("Discovering API structure...", total=None)

            openapi_discoverer = OpenAPIDiscoverer(http_client)
            rest_discoverer = RESTDiscoverer(http_client)
            tech_fingerprinter = TechnologyFingerprinter(http_client)

            # Discover API structure
            openapi_info = await openapi_discoverer.discover_openapi_spec(url)
            endpoints = await rest_discoverer.discover_endpoints(url)
            tech_info = await tech_fingerprinter.fingerprint_technology(url)

            progress.update(discovery_task, description="✓ Discovery completed")

            # Vulnerability scanning phase
            vuln_task = progress.add_task("Scanning for vulnerabilities...", total=None)

            # Initialize vulnerability detectors
            bola_detector = BOLADetector(http_client)
            bfla_detector = BFLADetector(http_client)
            mass_assignment_detector = MassAssignmentDetector(http_client)
            injection_tester = InjectionTester(http_client)
            ssrf_detector = SSRFDetector(http_client)
            business_logic_detector = BusinessLogicDetector(http_client)

            # Run vulnerability scans
            findings = []

            # Test each discovered endpoint
            for endpoint in endpoints:
                endpoint_url = endpoint.get('url', url)

                # Run vulnerability tests
                bola_results = await bola_detector.detect_bola_vulnerabilities(endpoint_url)
                findings.extend(bola_results)

                bfla_results = await bfla_detector.detect_bfla_vulnerabilities(endpoint_url)
                findings.extend(bfla_results)

                mass_assignment_results = await mass_assignment_detector.detect_mass_assignment(endpoint_url)
                findings.extend(mass_assignment_results)

                injection_results = await injection_tester.test_sql_injection(endpoint_url)
                findings.extend(injection_results)

                ssrf_results = await ssrf_detector.detect_ssrf_vulnerabilities(endpoint_url)
                findings.extend(ssrf_results)

                business_logic_results = await business_logic_detector.detect_business_logic_flaws(endpoint_url)
                findings.extend(business_logic_results)

            scan_results['findings'] = findings
            scan_results['total_requests'] = len(endpoints) * 6  # Rough estimate

            progress.update(vuln_task, description="✓ Vulnerability scanning completed")

            # AI Analysis phase (if enabled)
            if include_ai_analysis:
                ai_task = progress.add_task("Running AI analysis...", total=None)

                ai_analyzer = AIResponseAnalyzer(config)
                vulnerability_chainer = VulnerabilityChainer(ai_analyzer)

                # Analyze responses with AI
                ai_findings = []
                for finding in findings:
                    if 'response_data' in finding:
                        ai_results = await ai_analyzer.analyze_response(
                            finding['response_data'],
                            [AnalysisType.VULNERABILITY_DETECTION, AnalysisType.SENSITIVE_DATA_DETECTION]
                        )
                        ai_findings.extend(ai_results)

                # Build vulnerability chains
                exploitation_chains = await vulnerability_chainer.build_exploitation_chains(findings)

                # Add AI findings to results
                for ai_result in ai_findings:
                    for finding in ai_result.findings:
                        findings.append({
                            'id': f"ai_{len(findings)}",
                            'title': f"AI Detected: {finding.get('type', 'Unknown')}",
                            'description': finding.get('description',
                                                       'AI-powered analysis detected potential vulnerability'),
                            'severity': 'MEDIUM',
                            'risk_level': 'MEDIUM',
                            'cvss_score': None,
                            'cwe_id': None,
                            'owasp_category': 'AI Analysis',
                            'affected_endpoint': url,
                            'request_data': {},
                            'response_data': {},
                            'evidence': [finding],
                            'remediation': ', '.join(ai_result.recommendations),
                            'references': [],
                            'discovered_at': datetime.now()
                        })

                # Add exploitation chains
                for chain in exploitation_chains:
                    findings.append({
                        'id': f"chain_{len(findings)}",
                        'title': f"Vulnerability Chain: {chain.get('type', 'Unknown')}",
                        'description': chain.get('description',
                                                 'Multiple vulnerabilities can be chained for greater impact'),
                        'severity': chain.get('impact', 'HIGH'),
                        'risk_level': chain.get('impact', 'HIGH'),
                        'cvss_score': None,
                        'cwe_id': None,
                        'owasp_category': 'Vulnerability Chaining',
                        'affected_endpoint': url,
                        'request_data': {},
                        'response_data': {},
                        'evidence': chain.get('steps', []),
                        'remediation': 'Address individual vulnerabilities in the chain',
                        'references': [],
                        'discovered_at': datetime.now()
                    })

                scan_results['findings'] = findings
                progress.update(ai_task, description="✓ AI analysis completed")

            # Fuzzing phase
            fuzzing_task = progress.add_task("Advanced fuzzing...", total=None)

            fuzzer = FuzzerEngine(config, http_client)
            fuzzing_session = await fuzzer.start_fuzzing_session(
                url,
                strategy=FuzzingStrategy.INTELLIGENT,
                max_requests=min(max_requests, 100),
                request_delay=0.1
            )

            # Wait a bit for fuzzing to run
            await asyncio.sleep(5)

            # Get fuzzing status
            fuzzing_status = fuzzer.get_session_status(fuzzing_session)

            # Stop fuzzing session
            fuzzer.stop_session(fuzzing_session)

            progress.update(fuzzing_task,
                            description=f"✓ Fuzzing completed ({fuzzing_status.get('vulnerabilities_found', 0)} potential issues)")

            # Report generation phase
            report_task = progress.add_task("Generating report...", total=None)

            # Calculate scan duration
            scan_results['duration'] = (datetime.now() - scan_results['start_time']).total_seconds()

            # Convert findings to proper format for reporting
            from api_hunter.reporting.report_generator import VulnerabilityFinding

            vulnerability_findings = []
            for i, finding in enumerate(findings):
                vuln_finding = VulnerabilityFinding(
                    id=finding.get('id', f'finding_{i}'),
                    title=finding.get('title', 'Unknown Vulnerability'),
                    description=finding.get('description', 'No description available'),
                    severity=finding.get('severity', 'LOW'),
                    risk_level=finding.get('risk_level', 'LOW'),
                    cvss_score=finding.get('cvss_score'),
                    cwe_id=finding.get('cwe_id'),
                    owasp_category=finding.get('owasp_category', 'Unknown'),
                    affected_endpoint=finding.get('affected_endpoint', url),
                    request_data=finding.get('request_data', {}),
                    response_data=finding.get('response_data', {}),
                    evidence=finding.get('evidence', []),
                    remediation=finding.get('remediation', 'No remediation provided'),
                    references=finding.get('references', []),
                    discovered_at=finding.get('discovered_at', datetime.now())
                )
                vulnerability_findings.append(vuln_finding)

            # Generate report
            report_generator = ReportGenerator(config)

            # Map report types
            report_type_map = {
                'executive': ReportType.EXECUTIVE_SUMMARY,
                'technical': ReportType.TECHNICAL_DETAILED,
                'compliance': ReportType.COMPLIANCE_REPORT,
                'vulnerability': ReportType.VULNERABILITY_REPORT,
                'remediation': ReportType.REMEDIATION_GUIDE
            }

            report_format_map = {
                'html': ReportFormat.HTML,
                'pdf': ReportFormat.PDF,
                'json': ReportFormat.JSON,
                'markdown': ReportFormat.MARKDOWN
            }

            report_file = await report_generator.generate_report(
                vulnerability_findings,
                scan_results,
                report_type_map.get(report_type, ReportType.TECHNICAL_DETAILED),
                report_format_map.get(report_format, ReportFormat.HTML),
                output
            )

            progress.update(report_task, description="✓ Report generated")

        # Display results summary
        console.print("\n" + "=" * 60)
        console.print(f"[bold green]Scan completed successfully![/bold green]")
        console.print(f"[blue]Target:[/blue] {url}")
        console.print(f"[blue]Duration:[/blue] {scan_results['duration']:.2f} seconds")
        console.print(f"[blue]Total Requests:[/blue] {scan_results['total_requests']}")
        console.print(f"[blue]Vulnerabilities Found:[/blue] {len(findings)}")
        console.print(f"[blue]Report Generated:[/blue] {report_file}")

        # Show severity breakdown
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts:
            console.print("\n[bold]Severity Breakdown:[/bold]")
            table = Table()
            table.add_column("Severity", style="bold")
            table.add_column("Count", justify="right")

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in severity_counts:
                    color = {
                        'CRITICAL': 'red',
                        'HIGH': 'orange3',
                        'MEDIUM': 'yellow',
                        'LOW': 'green',
                        'INFO': 'blue'
                    }.get(severity, 'white')
                    table.add_row(f"[{color}]{severity}[/{color}]", str(severity_counts[severity]))

            console.print(table)

        console.print("=" * 60)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/red]")
        raise
    finally:
        await http_client.close()


@cli.command()
@click.argument('url')
@click.option('--strategy', type=click.Choice(['intelligent', 'breadth_first', 'depth_first', 'random', 'hybrid']),
              default='intelligent', help='Fuzzing strategy')
@click.option('--max-requests', default=1000, help='Maximum number of requests')
@click.option('--delay', default=0.1, help='Delay between requests in seconds')
@click.option('--timeout', default=30, help='Request timeout in seconds')
@click.option('--auth-header', help='Authentication header (format: "Header: Value")')
async def fuzz(url, strategy, max_requests, delay, timeout, auth_header):
    """Advanced intelligent fuzzing of API endpoints."""
    console.print(f"[bold blue]Starting advanced fuzzing of {url}[/bold blue]")

    config = get_config()
    configure_logging(config.log_level if hasattr(config, 'log_level') else 'INFO')

    from api_hunter.core.http_client import HTTPClient
    from api_hunter.fuzzing.fuzzer_engine import FuzzerEngine, FuzzingStrategy

    http_client = HTTPClient(config)
    fuzzer = FuzzerEngine(config, http_client)

    # Parse authentication header
    custom_headers = {}
    if auth_header:
        if ':' in auth_header:
            key, value = auth_header.split(':', 1)
            custom_headers[key.strip()] = value.strip()

    # Map strategy
    strategy_map = {
        'intelligent': FuzzingStrategy.INTELLIGENT,
        'breadth_first': FuzzingStrategy.BREADTH_FIRST,
        'depth_first': FuzzingStrategy.DEPTH_FIRST,
        'random': FuzzingStrategy.RANDOM,
        'hybrid': FuzzingStrategy.HYBRID
    }

    try:
        session_id = await fuzzer.start_fuzzing_session(
            url,
            strategy=strategy_map.get(strategy, FuzzingStrategy.INTELLIGENT),
            max_requests=max_requests,
            request_delay=delay,
            timeout=timeout,
            custom_headers=custom_headers
        )

        console.print(f"[green]Started fuzzing session: {session_id}[/green]")
        console.print(f"[blue]Strategy:[/blue] {strategy}")
        console.print(f"[blue]Max Requests:[/blue] {max_requests}")
        console.print(f"[blue]Delay:[/blue] {delay}s")

        # Monitor fuzzing progress
        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
        ) as progress:

            monitor_task = progress.add_task("Fuzzing in progress...", total=max_requests)

            last_requests = 0
            while True:
                await asyncio.sleep(2)

                status = fuzzer.get_session_status(session_id)
                if 'error' in status:
                    break

                current_requests = status['total_requests']
                vulnerabilities = status['vulnerabilities_found']
                unique_responses = status['unique_responses']
                progress_percent = status['progress']

                progress.update(
                    monitor_task,
                    completed=current_requests,
                    description=f"Fuzzing... {current_requests}/{max_requests} requests | "
                                f"{vulnerabilities} vulns | {unique_responses} unique responses | "
                                f"{progress_percent:.1f}% complete"
                )

                if current_requests >= max_requests or progress_percent >= 100:
                    break

                last_requests = current_requests

        # Get final status
        final_status = fuzzer.get_session_status(session_id)

        console.print("\n" + "=" * 60)
        console.print("[bold green]Fuzzing completed![/bold green]")
        console.print(f"[blue]Total Requests:[/blue] {final_status.get('total_requests', 0)}")
        console.print(f"[blue]Vulnerabilities Found:[/blue] {final_status.get('vulnerabilities_found', 0)}")
        console.print(f"[blue]Unique Responses:[/blue] {final_status.get('unique_responses', 0)}")
        console.print(f"[blue]Duration:[/blue] {final_status.get('elapsed_time', 0):.2f} seconds")
        console.print(f"[blue]Requests/Second:[/blue] {final_status.get('requests_per_second', 0):.2f}")
        console.print("=" * 60)

    except KeyboardInterrupt:
        console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
        fuzzer.stop_session(session_id)
    except Exception as e:
        console.print(f"\n[red]Error during fuzzing: {e}[/red]")
        raise
    finally:
        await http_client.close()


@cli.command()
@click.argument('url')
@click.option('--analysis-types', multiple=True,
              type=click.Choice(['vulnerability', 'sensitive_data', 'error', 'pattern', 'business_logic']),
              default=['vulnerability', 'sensitive_data'],
              help='Types of AI analysis to perform')
@click.option('--output', '-o', help='Output JSON file for results')
async def ai_analyze(url, analysis_types, output):
    """AI-powered analysis of API responses."""
    console.print(f"[bold blue]Starting AI analysis of {url}[/bold blue]")

    config = get_config()
    configure_logging(config.log_level if hasattr(config, 'log_level') else 'INFO')

    from api_hunter.core.http_client import HTTPClient
    from api_hunter.core.ai_analyzer import AIResponseAnalyzer, AnalysisType

    http_client = HTTPClient(config)
    ai_analyzer = AIResponseAnalyzer(config)

    # Map analysis types
    analysis_type_map = {
        'vulnerability': AnalysisType.VULNERABILITY_DETECTION,
        'sensitive_data': AnalysisType.SENSITIVE_DATA_DETECTION,
        'error': AnalysisType.ERROR_ANALYSIS,
        'pattern': AnalysisType.PATTERN_RECOGNITION,
        'business_logic': AnalysisType.BUSINESS_LOGIC_ANALYSIS
    }

    selected_types = [analysis_type_map[t] for t in analysis_types]

    try:
        with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
        ) as progress:

            task = progress.add_task("Fetching response...", total=None)

            # Get response from URL
            response = await http_client.request('GET', url)

            progress.update(task, description="Analyzing with AI...")

            # Perform AI analysis
            response_data = {
                'status_code': response.get('status_code'),
                'headers': response.get('headers', {}),
                'body': response.get('body', '')
            }

            ai_results = await ai_analyzer.analyze_response(response_data, selected_types)

            progress.update(task, description="✓ Analysis completed")

        # Display results
        console.print("\n" + "=" * 60)
        console.print("[bold green]AI Analysis Results[/bold green]")

        total_findings = 0
        for result in ai_results:
            console.print(f"\n[bold]{result.analysis_type.value.replace('_', ' ').title()}[/bold]")
            console.print(f"[blue]Confidence:[/blue] {result.confidence:.2f}")
            console.print(f"[blue]Processing Time:[/blue] {result.processing_time:.3f}s")
            console.print(f"[blue]Findings:[/blue] {len(result.findings)}")

            total_findings += len(result.findings)

            if result.findings:
                for i, finding in enumerate(result.findings[:3], 1):  # Show first 3 findings
                    console.print(
                        f"  {i}. {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')[:100]}...")

                if len(result.findings) > 3:
                    console.print(f"  ... and {len(result.findings) - 3} more findings")

            if result.recommendations:
                console.print(f"[yellow]Recommendations:[/yellow]")
                for rec in result.recommendations[:3]:  # Show first 3 recommendations
                    console.print(f"  • {rec}")

        console.print(f"\n[bold]Total Findings Across All Analysis Types:[/bold] {total_findings}")
        console.print("=" * 60)

        # Save results to JSON if requested
        if output:
            results_data = []
            for result in ai_results:
                results_data.append({
                    'analysis_type': result.analysis_type.value,
                    'confidence': result.confidence,
                    'findings': result.findings,
                    'recommendations': result.recommendations,
                    'metadata': result.metadata,
                    'processing_time': result.processing_time
                })

            with open(output, 'w') as f:
                json.dump(results_data, f, indent=2, default=str)

            console.print(f"[green]Results saved to {output}[/green]")

    except Exception as e:
        console.print(f"\n[red]Error during AI analysis: {e}[/red]")
        raise
    finally:
        await http_client.close()


@cli.command()
@click.argument('target_url')
@click.option('--scan-type',
              type=click.Choice(['discovery', 'full', 'auth', 'fuzzing', 'custom']),
              default='discovery', help='Type of scan to perform')
@click.option('--output', '-o', help='Output file for results')
@click.option('--format', 'output_format',
              type=click.Choice(['json', 'html', 'pdf', 'csv']),
              default='json', help='Output format')
@click.option('--threads', '-t', default=10, help='Number of concurrent threads')
@click.option('--timeout', default=30, help='Request timeout in seconds')
@click.option('--rate-limit', default=10, help='Requests per second')
@click.option('--proxy', help='Proxy URL (e.g., http://localhost:8080)')
@click.option('--headers', multiple=True, help='Custom headers (format: "Name: Value")')
@click.option('--cookies', help='Cookies (format: "name1=value1; name2=value2")')
@click.option('--auth-token', help='Authentication token')
@click.option('--auth-header', default='Authorization', help='Authentication header name')
@click.option('--wordlist', help='Custom wordlist file')
@click.option('--exclude-status', multiple=True, type=int, help='Exclude HTTP status codes')
@click.option('--include-status', multiple=True, type=int, help='Include only these HTTP status codes')
@click.option('--max-depth', default=3, help='Maximum directory depth for discovery')
@click.option('--delay', default=0, help='Delay between requests (seconds)')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode (minimal output)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def scan(ctx, target_url, scan_type, output, output_format, threads, timeout,
         rate_limit, proxy, headers, cookies, auth_token, auth_header, wordlist,
         exclude_status, include_status, max_depth, delay, quiet, verbose):
    """Perform a security scan on the target API."""

    ctx.obj['quiet'] = quiet

    if not quiet:
        console.print(f"\n[bold green]Starting {scan_type} scan of {target_url}[/bold green]\n")

    # Prepare scan configuration
    scan_config = {
        'target_url': target_url,
        'scan_type': scan_type,
        'threads': threads,
        'timeout': timeout,
        'rate_limit': rate_limit,
        'max_depth': max_depth,
        'delay': delay,
        'proxy': proxy,
        'headers': dict(h.split(':', 1) for h in headers) if headers else {},
        'cookies': cookies,
        'auth_token': auth_token,
        'auth_header': auth_header,
        'wordlist': wordlist,
        'exclude_status': list(exclude_status),
        'include_status': list(include_status),
        'output': output,
        'output_format': output_format,
        'verbose': verbose
    }

    try:
        # Run the scan
        result = asyncio.run(run_scan(scan_config))

        if not quiet:
            display_scan_results(result)

        # Save results if output specified
        if output:
            save_results(result, output, output_format)
            console.print(f"\n[green]Results saved to {output}[/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/red]")
        if ctx.obj.get('debug'):
            console.print_exception()
        sys.exit(1)


async def run_scan(config: dict):
    """Run the actual scan with the given configuration."""
    # This is a placeholder - actual implementation will be added
    # when we build the discovery and scanning engines

    from api_hunter.core.http_client import create_http_client, RequestConfig, RateLimitConfig

    # Create HTTP client
    request_config = RequestConfig(
        timeout=config['timeout'],
        proxy=config['proxy'],
        headers=config['headers']
    )

    rate_limit_config = RateLimitConfig(
        requests_per_second=config['rate_limit']
    )

    async with create_http_client(
            request_config=request_config,
            rate_limit_config=rate_limit_config
    ) as client:

        # Placeholder scan logic
        console.print("[cyan]Testing target accessibility...[/cyan]")

        try:
            response = await client.get(config['target_url'])
            console.print(f"[green]Target is accessible (Status: {response.status_code})[/green]")

            return {
                'target_url': config['target_url'],
                'scan_type': config['scan_type'],
                'status': 'success',
                'endpoints_found': 0,
                'vulnerabilities_found': 0,
                'total_requests': 1,
                'scan_time': '< 1s'
            }

        except Exception as e:
            console.print(f"[red]Target is not accessible: {e}[/red]")
            return {
                'target_url': config['target_url'],
                'scan_type': config['scan_type'],
                'status': 'error',
                'error': str(e)
            }


def display_scan_results(result: dict):
    """Display scan results in a formatted table."""

    if result.get('status') == 'error':
        console.print(f"[red]Scan failed: {result.get('error')}[/red]")
        return

    # Create results table
    table = Table(title="Scan Results")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Target URL", result['target_url'])
    table.add_row("Scan Type", result['scan_type'])
    table.add_row("Status", f"[green]{result['status']}[/green]")
    table.add_row("Endpoints Found", str(result.get('endpoints_found', 0)))
    table.add_row("Vulnerabilities Found", str(result.get('vulnerabilities_found', 0)))
    table.add_row("Total Requests", str(result.get('total_requests', 0)))
    table.add_row("Scan Time", result.get('scan_time', 'Unknown'))

    console.print(table)


def save_results(result: dict, output_path: str, format: str):
    """Save scan results to file."""
    import json

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    if format == 'json':
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
    else:
        # Placeholder for other formats
        console.print(f"[yellow]Format {format} not yet implemented, saving as JSON[/yellow]")
        with open(output_file.with_suffix('.json'), 'w') as f:
            json.dump(result, f, indent=2)


@cli.command()
def config():
    """Show current configuration."""
    config = get_config()

    table = Table(title="API Hunter Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("App Name", config.app_name)
    table.add_row("Version", config.version)
    table.add_row("Debug Mode", str(config.debug))
    table.add_row("Log Level", config.log_level)
    table.add_row("Redis URL", config.get_redis_url())
    table.add_row("Max Concurrent Requests", str(config.scanning.max_concurrent_requests))
    table.add_row("Request Timeout", f"{config.scanning.request_timeout}s")
    table.add_row("Rate Limit", f"{config.scanning.rate_limit} req/s")

    console.print(table)


@cli.command()
@click.option('--list-plugins', is_flag=True, help='List available plugins')
@click.option('--enable', help='Enable a plugin')
@click.option('--disable', help='Disable a plugin')
def plugins(list_plugins, enable, disable):
    """Manage API Hunter plugins."""

    if list_plugins:
        console.print("[cyan]Available Plugins:[/cyan]")
        # Placeholder - actual plugin discovery will be implemented later
        plugins_list = [
            ("burp_integration", "enabled", "Burp Suite integration"),
            ("slack_notifications", "enabled", "Slack webhook notifications"),
            ("custom_wordlists", "disabled", "Custom wordlist management"),
            ("ai_analysis", "disabled", "AI-powered analysis"),
        ]

        table = Table()
        table.add_column("Plugin", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Description", style="dim")

        for name, status, description in plugins_list:
            status_color = "green" if status == "enabled" else "red"
            table.add_row(name, f"[{status_color}]{status}[/{status_color}]", description)

        console.print(table)

    if enable:
        console.print(f"[green]Plugin '{enable}' enabled[/green]")

    if disable:
        console.print(f"[yellow]Plugin '{disable}' disabled[/yellow]")


@cli.command()
def version():
    """Show version information."""
    info = f"""
[bold]API Hunter[/bold] v{__version__}

[dim]Advanced Bug Bounty Tool for API Security Testing
Built with ❤️ for the security community[/dim]

[cyan]Features:[/cyan]
• API Discovery & Enumeration
• OWASP API Top 10 Testing
• JWT & OAuth Security Analysis
• GraphQL Introspection
• Business Logic Testing
• AI-Powered Analysis
• Professional Reporting
"""
    console.print(Panel(info, title="Version Information", border_style="blue"))


@cli.command()
@click.argument('template')
@click.option('--count', default=10, help='Number of payloads to generate')
@click.option('--output', '-o', help='Output file for payloads')
@click.option('--format', 'output_format',
              type=click.Choice(['hex', 'raw', 'c-array']),
              default='hex', help='Output format')
@click.option('--protocol', help='Generate protocol-specific payloads (grpc, websocket, custom)')
def generate_binary_payloads(template, count, output, output_format, protocol):
    """Generate binary payloads using template syntax.
    
    Template syntax examples:
    \b
    - {R[0,255,"B"]} - Range 0-255 as single byte
    - {[0,1,2,3]} - Array of specific values  
    - {r[10,5]} - 5 random sequences of 10 bytes each
    - {@file.txt} - Load payloads from file
    
    Example: generate-binary-payloads '{[0,1]}FF{R[1,10,"B"]}'
    """
    console.print(f"[bold blue]Generating binary payloads from template: {template}[/bold blue]")

    from api_hunter.fuzzing.binary_payload_generator import BinaryPayloadGenerator, EnhancedPayloadGenerator

    payloads = []

    if protocol:
        # Generate protocol-specific payloads
        enhanced_gen = EnhancedPayloadGenerator()
        payloads = enhanced_gen.generate_protocol_payloads(protocol)[:count]
        console.print(f"[green]Generated {len(payloads)} {protocol} protocol payloads[/green]")
    else:
        # Generate from template
        try:
            generator = BinaryPayloadGenerator(template)
            payloads = generator.generate_all(count)
            console.print(f"[green]Generated {len(payloads)} payloads from template[/green]")
        except Exception as e:
            console.print(f"[red]Error generating payloads: {e}[/red]")
            return

    if not payloads:
        console.print("[yellow]No payloads generated[/yellow]")
        return

    # Display payloads
    console.print("\n[bold]Generated Payloads:[/bold]")
    for i, payload in enumerate(payloads[:10], 1):  # Show first 10
        if output_format == 'hex':
            hex_str = payload.hex()
            formatted = ' '.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))
            console.print(f"{i:2d}: {formatted}")
        elif output_format == 'raw':
            console.print(f"{i:2d}: {payload}")
        elif output_format == 'c-array':
            c_array = ', '.join(f'0x{b:02x}' for b in payload)
            console.print(f"{i:2d}: {{ {c_array} }}")

    if len(payloads) > 10:
        console.print(f"... and {len(payloads) - 10} more payloads")

    # Save to file if requested
    if output:
        try:
            with open(output, 'w') as f:
                for i, payload in enumerate(payloads):
                    if output_format == 'hex':
                        hex_str = payload.hex()
                        formatted = ' '.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))
                        f.write(f"{formatted}\n")
                    elif output_format == 'raw':
                        f.write(f"{payload}\n")
                    elif output_format == 'c-array':
                        c_array = ', '.join(f'0x{b:02x}' for b in payload)
                        f.write(f"{{ {c_array} }},\n")
            console.print(f"[green]Payloads saved to {output}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving to file: {e}[/red]")


@cli.command()
@click.option('--targets', required=True, help='Comma-separated list of target URLs')
@click.option('--scan-types', default='discovery,vulnerabilities',
              help='Comma-separated list of scan types')
@click.option('--severity-threshold', default='MEDIUM',
              type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
              help='Minimum severity threshold for failing pipeline')
@click.option('--fail-on-vulns/--no-fail-on-vulns', default=True,
              help='Whether to fail pipeline on vulnerabilities')
@click.option('--report-formats', default='json,html',
              help='Comma-separated list of report formats')
@click.option('--output-dir', default='./security-reports',
              help='Output directory for reports')
@click.option('--max-duration', default=600, type=int,
              help='Maximum scan duration in seconds')
@click.option('--generate-config',
              type=click.Choice(['github-actions', 'gitlab-ci', 'jenkins']),
              help='Generate CI/CD configuration file')
@click.option('--config-output-dir', default='.',
              help='Output directory for generated CI/CD config')
async def cicd_scan(targets, scan_types, severity_threshold, fail_on_vulns,
                    report_formats, output_dir, max_duration, generate_config,
                    config_output_dir):
    """Execute security scan optimized for CI/CD environments."""

    # Import CI/CD manager
    from api_hunter.integrations.cicd_manager import CICDManager, ScanConfiguration, CICDPlatform

    cicd_manager = CICDManager()
    await cicd_manager.initialize()

    # Parse targets and other comma-separated values
    target_list = [t.strip() for t in targets.split(',')]
    scan_type_list = [s.strip() for s in scan_types.split(',')]
    report_format_list = [r.strip() for r in report_formats.split(',')]

    # If generating config, do that and exit
    if generate_config:
        platform_map = {
            'github-actions': CICDPlatform.GITHUB_ACTIONS,
            'gitlab-ci': CICDPlatform.GITLAB_CI,
            'jenkins': CICDPlatform.JENKINS
        }

        platform = platform_map[generate_config]
        scan_config = ScanConfiguration(
            target_urls=target_list,
            scan_types=scan_type_list,
            severity_threshold=severity_threshold,
            fail_on_vulnerabilities=fail_on_vulns,
            report_formats=report_format_list,
            max_scan_duration=max_duration
        )

        config_content = cicd_manager.generate_pipeline_config(
            platform, scan_config, config_output_dir
        )

        console.print(f"[green]Generated {generate_config} configuration[/green]")
        console.print(f"[blue]Configuration saved to {config_output_dir}[/blue]")
        return

    # Detect CI/CD environment
    detected_platform = cicd_manager.detect_cicd_environment()
    if detected_platform:
        console.print(f"[cyan]Detected CI/CD platform: {detected_platform.value}[/cyan]")

    # Get environment configuration
    env_config = cicd_manager.get_environment_config()

    # Override with environment variables if present
    if env_config.get('targets'):
        target_list = env_config['targets']
    if env_config.get('scan_types'):
        scan_type_list = env_config['scan_types']
    if env_config.get('severity_threshold'):
        severity_threshold = env_config['severity_threshold']
    if 'fail_on_vulnerabilities' in env_config:
        fail_on_vulns = env_config['fail_on_vulnerabilities']
    if env_config.get('report_formats'):
        report_format_list = env_config['report_formats']
    if env_config.get('output_dir'):
        output_dir = env_config['output_dir']
    if env_config.get('max_duration'):
        max_duration = env_config['max_duration']

    console.print(f"[bold blue]Starting CI/CD security scan[/bold blue]")
    console.print(f"[blue]Targets:[/blue] {', '.join(target_list)}")
    console.print(f"[blue]Scan Types:[/blue] {', '.join(scan_type_list)}")
    console.print(f"[blue]Severity Threshold:[/blue] {severity_threshold}")
    console.print(f"[blue]Fail on Vulnerabilities:[/blue] {fail_on_vulns}")
    console.print(f"[blue]Report Formats:[/blue] {', '.join(report_format_list)}")
    console.print(f"[blue]Output Directory:[/blue] {output_dir}")

    try:
        # Execute the CI/CD scan
        result = await cicd_manager.execute_cicd_scan(
            targets=target_list,
            scan_types=scan_type_list,
            severity_threshold=severity_threshold,
            fail_on_vulnerabilities=fail_on_vulns,
            report_formats=report_format_list,
            output_dir=output_dir,
            max_duration=max_duration
        )

        # Display results
        console.print("\n" + "=" * 60)
        console.print(
            f"[bold {'green' if result.success else 'red'}]CI/CD Scan {'Completed' if result.success else 'Failed'}[/bold {'green' if result.success else 'red'}]")
        console.print(f"[blue]Scan ID:[/blue] {result.scan_id}")
        console.print(f"[blue]Duration:[/blue] {result.scan_duration:.2f} seconds")
        console.print(f"[blue]Vulnerabilities Found:[/blue] {result.vulnerabilities_found}")

        if result.vulnerabilities_found > 0:
            console.print(f"[red]High Severity:[/red] {result.high_severity_count}")
            console.print(f"[yellow]Medium Severity:[/yellow] {result.medium_severity_count}")
            console.print(f"[green]Low Severity:[/green] {result.low_severity_count}")

        if result.report_paths:
            console.print(f"[blue]Reports Generated:[/blue]")
            for report_path in result.report_paths:
                console.print(f"  • {report_path}")

        if result.error_message:
            console.print(f"[red]Error:[/red] {result.error_message}")

        console.print("=" * 60)

        # Send notifications if plugins available
        try:
            from api_hunter.plugins.plugin_manager import PluginManager
            from api_hunter.plugins.base_plugin import PluginType

            plugin_manager = PluginManager()
            await plugin_manager.initialize()

            # Send notifications
            if result.success:
                await plugin_manager.send_notifications(
                    f"CI/CD scan completed successfully. Found {result.vulnerabilities_found} vulnerabilities.",
                    "info" if result.vulnerabilities_found == 0 else "warning"
                )
            else:
                await plugin_manager.send_notifications(
                    f"CI/CD scan failed: {result.error_message or 'Unknown error'}",
                    "error"
                )

            await plugin_manager.cleanup()

        except Exception as e:
            console.print(f"[yellow]Warning: Failed to send notifications: {e}[/yellow]")

        # Exit with appropriate code for CI/CD
        sys.exit(result.exit_code)

    except Exception as e:
        console.print(f"[red]CI/CD scan failed: {e}[/red]")
        sys.exit(2)


if __name__ == '__main__':
    cli()
