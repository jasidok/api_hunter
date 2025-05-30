#!/usr/bin/env python3
"""
API Hunter - Advanced Bug Bounty Tool for API Security Testing

Main CLI entry point for the application.
"""

import sys
import asyncio
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

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
    table.add_row("Database URL", config.get_database_url())
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
            ("ai_analysis", "disabled", "AI-powered response analysis"),
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


if __name__ == '__main__':
    cli()
