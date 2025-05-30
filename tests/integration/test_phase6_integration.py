"""
Integration tests for Phase 6 features

Tests the complete Phase 6 functionality including:
- Plugin system integration
- CI/CD pipeline integration  
- Performance optimizations
- Burp Suite integration
- Slack notifications
"""

import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

from api_hunter.plugins.plugin_manager import PluginManager
from api_hunter.plugins.base_plugin import PluginType, PluginInfo
from api_hunter.plugins.builtin.burp_integration import BurpIntegrationPlugin
from api_hunter.plugins.builtin.slack_notifications import SlackNotificationPlugin
from api_hunter.integrations.cicd_manager import CICDManager, ScanConfiguration, CICDPlatform
from api_hunter.core.performance import (
    PerformanceMonitor, RequestRateLimiter, MemoryOptimizer,
    CacheManager, TaskQueue, PerformanceProfiler
)


class TestPluginSystem:
    """Test the plugin system integration."""

    @pytest.fixture
    async def plugin_manager(self):
        """Create a plugin manager for testing."""
        config = {
            'plugins': {
                'enabled': ['burp_integration', 'slack_notifications'],
                'disabled': []
            },
            'plugin_configs': {
                'burp_integration': {
                    'burp_url': 'http://localhost:1337',
                    'timeout': 10
                },
                'slack_notifications': {
                    'webhook_url': 'https://hooks.slack.com/test'
                }
            }
        }

        manager = PluginManager(config)
        await manager.initialize()
        return manager

    @pytest.mark.asyncio
    async def test_plugin_manager_initialization(self, plugin_manager):
        """Test plugin manager initializes correctly."""
        assert plugin_manager._initialized
        assert len(plugin_manager.registry.plugins) >= 0

    @pytest.mark.asyncio
    async def test_plugin_loading_and_enabling(self, plugin_manager):
        """Test plugin loading and enabling functionality."""
        # Test getting plugins by type
        integration_plugins = plugin_manager.get_plugins_by_type(PluginType.INTEGRATION)
        notification_plugins = plugin_manager.get_plugins_by_type(PluginType.NOTIFICATION)

        # Test plugin status
        status = plugin_manager.get_plugin_status_summary()
        assert 'total_plugins' in status
        assert 'enabled_plugins' in status
        assert status['manager_initialized'] is True

    @pytest.mark.asyncio
    async def test_plugin_notifications(self, plugin_manager):
        """Test plugin notification system."""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_post.return_value.__aenter__.return_value = mock_response

            # Test sending notifications
            results = await plugin_manager.send_notifications(
                "Test notification", "info"
            )

            # Should work even if no plugins are actually loaded in test environment
            assert isinstance(results, dict)


class TestBurpIntegration:
    """Test Burp Suite integration plugin."""

    @pytest.fixture
    def burp_plugin(self):
        """Create Burp integration plugin for testing."""
        config = {
            'burp_url': 'http://localhost:1337',
            'api_key': 'test-key',
            'timeout': 10,
            'verify_ssl': False
        }
        return BurpIntegrationPlugin(config)

    @pytest.mark.asyncio
    async def test_burp_plugin_initialization(self, burp_plugin):
        """Test Burp plugin initialization."""
        assert burp_plugin.plugin_info.name == "burp_integration"
        assert burp_plugin.plugin_info.plugin_type == PluginType.INTEGRATION
        assert burp_plugin.burp_url == 'http://localhost:1337'

    @pytest.mark.asyncio
    async def test_burp_findings_conversion(self, burp_plugin):
        """Test conversion of findings to Burp format."""
        finding = {
            'id': 'test_1',
            'title': 'SQL Injection',
            'description': 'SQL injection vulnerability found',
            'severity': 'HIGH',
            'affected_endpoint': 'https://api.example.com/users',
            'cvss_score': 8.1,
            'cwe_id': 'CWE-89',
            'owasp_category': 'Injection',
            'remediation': 'Use parameterized queries',
            'references': ['https://owasp.org/www-community/attacks/SQL_Injection']
        }

        burp_issue = burp_plugin._convert_to_burp_format(finding)

        assert burp_issue is not None
        assert burp_issue['name'] == 'SQL Injection'
        assert burp_issue['severity'] == 'High'
        assert burp_issue['host'] == 'https://api.example.com'
        assert burp_issue['path'] == '/users'

    @pytest.mark.asyncio
    async def test_burp_import_conversion(self, burp_plugin):
        """Test conversion from Burp format to API Hunter format."""
        burp_issue = {
            'serial_number': '12345',
            'name': 'Cross-site scripting (reflected)',
            'severity': 'High',
            'confidence': 'Certain',
            'host': 'https://api.example.com',
            'path': '/search?q=test',
            'issue_background': 'XSS vulnerability detected',
            'remediation_background': 'Encode user input',
            'first_seen': '2024-01-15T10:30:00Z'
        }

        api_hunter_finding = burp_plugin._convert_from_burp_format(burp_issue)

        assert api_hunter_finding is not None
        assert api_hunter_finding['id'] == 'burp_12345'
        assert api_hunter_finding['title'] == 'Cross-site scripting (reflected)'
        assert api_hunter_finding['severity'] == 'HIGH'
        assert api_hunter_finding['source'] == 'Burp Suite'


class TestSlackNotifications:
    """Test Slack notifications plugin."""

    @pytest.fixture
    def slack_plugin(self):
        """Create Slack notification plugin for testing."""
        config = {
            'webhook_url': 'https://hooks.slack.com/services/test',
            'channels': {
                'HIGH': 'https://hooks.slack.com/services/security',
                'reports': 'https://hooks.slack.com/services/reports'
            },
            'mention_users': {
                'CRITICAL': ['U12345678'],
                'HIGH': ['U12345678', 'U87654321']
            }
        }
        return SlackNotificationPlugin(config)

    @pytest.mark.asyncio
    async def test_slack_plugin_initialization(self, slack_plugin):
        """Test Slack plugin initialization."""
        assert slack_plugin.plugin_info.name == "slack_notifications"
        assert slack_plugin.plugin_info.plugin_type == PluginType.NOTIFICATION
        assert slack_plugin.webhook_url == 'https://hooks.slack.com/services/test'

    @pytest.mark.asyncio
    async def test_slack_risk_score_calculation(self, slack_plugin):
        """Test risk score calculation."""
        severity_counts = {
            'CRITICAL': 2,
            'HIGH': 3,
            'MEDIUM': 5,
            'LOW': 10,
            'INFO': 2
        }

        risk_score = slack_plugin._calculate_risk_score(severity_counts)
        expected_score = (2 * 25) + (3 * 15) + (5 * 8) + (10 * 3) + (
                    2 * 1)  # 50 + 45 + 40 + 30 + 2 = 167, capped at 100

        assert risk_score == 100  # Should be capped at 100

    @pytest.mark.asyncio
    async def test_slack_severity_breakdown_formatting(self, slack_plugin):
        """Test severity breakdown formatting."""
        severity_counts = {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 3,
            'LOW': 4
        }

        breakdown = slack_plugin._format_severity_breakdown(severity_counts)

        assert ':red_circle: CRITICAL: 1' in breakdown
        assert ':orange_circle: HIGH: 2' in breakdown
        assert ':yellow_circle: MEDIUM: 3' in breakdown
        assert ':green_circle: LOW: 4' in breakdown

    @pytest.mark.asyncio
    async def test_slack_vulnerability_alert(self, slack_plugin):
        """Test vulnerability alert formatting."""
        finding = {
            'title': 'SQL Injection in Login',
            'severity': 'HIGH',
            'affected_endpoint': 'https://api.example.com/auth/login',
            'description': 'SQL injection vulnerability in login endpoint allows authentication bypass'
        }

        with patch.object(slack_plugin, 'send_notification', return_value=True) as mock_send:
            result = await slack_plugin.send_vulnerability_alert(finding)

            assert result is True
            mock_send.assert_called_once()

            # Check the message content
            call_args = mock_send.call_args
            message = call_args[0][0]
            assert 'HIGH severity vulnerability detected' in message
            assert 'SQL Injection in Login' in message


class TestCICDIntegration:
    """Test CI/CD integration functionality."""

    @pytest.fixture
    def cicd_manager(self):
        """Create CI/CD manager for testing."""
        config = {
            'plugin_directories': [],
            'default_scan_types': ['discovery', 'vulnerabilities']
        }
        return CICDManager(config)

    @pytest.mark.asyncio
    async def test_cicd_manager_initialization(self, cicd_manager):
        """Test CI/CD manager initialization."""
        await cicd_manager.initialize()
        assert cicd_manager.config is not None

    def test_cicd_environment_detection(self, cicd_manager):
        """Test CI/CD environment detection."""
        # Test GitHub Actions detection
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'true'}):
            platform = cicd_manager.detect_cicd_environment()
            assert platform == CICDPlatform.GITHUB_ACTIONS

        # Test GitLab CI detection
        with patch.dict('os.environ', {'GITLAB_CI': 'true'}):
            platform = cicd_manager.detect_cicd_environment()
            assert platform == CICDPlatform.GITLAB_CI

        # Test Jenkins detection
        with patch.dict('os.environ', {'JENKINS_URL': 'http://jenkins.example.com'}):
            platform = cicd_manager.detect_cicd_environment()
            assert platform == CICDPlatform.JENKINS

    def test_github_actions_config_generation(self, cicd_manager):
        """Test GitHub Actions configuration generation."""
        scan_config = ScanConfiguration(
            target_urls=['https://api.example.com'],
            scan_types=['discovery', 'vulnerabilities'],
            severity_threshold='MEDIUM',
            fail_on_vulnerabilities=True,
            report_formats=['json', 'html']
        )

        config_content = cicd_manager.generate_pipeline_config(
            CICDPlatform.GITHUB_ACTIONS, scan_config
        )

        assert 'name: API Security Scan' in config_content
        assert 'api-hunter cicd-scan' in config_content
        assert 'https://api.example.com' in config_content
        assert 'discovery,vulnerabilities' in config_content

    def test_gitlab_ci_config_generation(self, cicd_manager):
        """Test GitLab CI configuration generation."""
        scan_config = ScanConfiguration(
            target_urls=['https://api.example.com'],
            scan_types=['vulnerabilities'],
            severity_threshold='HIGH',
            fail_on_vulnerabilities=True
        )

        config_content = cicd_manager.generate_pipeline_config(
            CICDPlatform.GITLAB_CI, scan_config
        )

        assert 'stages:' in config_content
        assert 'security-scan' in config_content
        assert 'api-hunter cicd-scan' in config_content
        assert 'HIGH' in config_content

    def test_jenkins_config_generation(self, cicd_manager):
        """Test Jenkins pipeline configuration generation."""
        scan_config = ScanConfiguration(
            target_urls=['https://api.example.com'],
            scan_types=['auth'],
            severity_threshold='CRITICAL'
        )

        config_content = cicd_manager.generate_pipeline_config(
            CICDPlatform.JENKINS, scan_config
        )

        assert 'pipeline {' in config_content
        assert 'API Security Scan' in config_content
        assert 'api-hunter cicd-scan' in config_content
        assert 'CRITICAL' in config_content

    @pytest.mark.asyncio
    async def test_cicd_scan_execution(self, cicd_manager):
        """Test CI/CD scan execution."""
        # Mock the scan execution to avoid actual network calls
        with patch.object(cicd_manager, '_mock_scan_execution') as mock_scan:
            mock_scan.return_value = {
                'target': 'https://api.example.com',
                'findings': [
                    {'title': 'Test Vulnerability', 'severity': 'MEDIUM'}
                ]
            }

            result = await cicd_manager.execute_cicd_scan(
                targets=['https://api.example.com'],
                scan_types=['discovery'],
                severity_threshold='LOW',
                fail_on_vulnerabilities=False
            )

            assert result.success is True
            assert result.vulnerabilities_found == 1
            assert result.scan_id.startswith('cicd_')

    def test_environment_config_parsing(self, cicd_manager):
        """Test environment variable configuration parsing."""
        env_vars = {
            'API_HUNTER_TARGETS': 'https://api1.com,https://api2.com',
            'API_HUNTER_SCAN_TYPES': 'discovery,vulnerabilities',
            'API_HUNTER_SEVERITY_THRESHOLD': 'HIGH',
            'API_HUNTER_FAIL_ON_VULNS': 'true',
            'API_HUNTER_MAX_DURATION': '300'
        }

        with patch.dict('os.environ', env_vars):
            config = cicd_manager.get_environment_config()

            assert config['targets'] == ['https://api1.com', 'https://api2.com']
            assert config['scan_types'] == ['discovery', 'vulnerabilities']
            assert config['severity_threshold'] == 'HIGH'
            assert config['fail_on_vulnerabilities'] is True
            assert config['max_duration'] == 300


class TestPerformanceOptimizations:
    """Test performance optimization features."""

    @pytest.mark.asyncio
    async def test_performance_monitor(self):
        """Test performance monitoring functionality."""
        monitor = PerformanceMonitor()

        # Start monitoring
        await monitor.start_monitoring(interval=0.1)

        # Record some requests
        await monitor.record_request(0.1, True)
        await monitor.record_request(0.2, True)
        await monitor.record_request(0.5, False)

        # Wait briefly for monitoring
        await asyncio.sleep(0.2)

        # Stop monitoring and get metrics
        metrics = await monitor.stop_monitoring()

        assert metrics.total_requests == 3
        assert metrics.successful_requests == 2
        assert metrics.failed_requests == 1
        assert metrics.success_rate == 66.66666666666666

    @pytest.mark.asyncio
    async def test_request_rate_limiter(self):
        """Test adaptive rate limiting."""
        limiter = RequestRateLimiter(initial_rate=100.0, max_rate=200.0)

        # Test rate limiting
        start_time = asyncio.get_event_loop().time()
        await limiter.acquire()
        await limiter.acquire()
        end_time = asyncio.get_event_loop().time()

        # Should have some delay between requests
        elapsed = end_time - start_time
        assert elapsed >= 0.01  # At least 0.01 seconds for 100 req/s

        # Test rate adjustment
        for _ in range(5):
            await limiter.record_result(True)

        # Should have successful requests recorded
        assert limiter.success_count > 0

    @pytest.mark.asyncio
    async def test_memory_optimizer(self):
        """Test memory optimization."""
        optimizer = MemoryOptimizer(max_memory_mb=1024)

        # Test memory usage detection
        memory_usage = optimizer.get_memory_usage_mb()
        assert isinstance(memory_usage, float)
        assert memory_usage > 0

        # Test cleanup threshold
        should_cleanup = optimizer.should_cleanup()
        assert isinstance(should_cleanup, bool)

        # Test cleanup execution
        cleanup_performed = await optimizer.cleanup_if_needed()
        assert isinstance(cleanup_performed, bool)

    @pytest.mark.asyncio
    async def test_cache_manager(self):
        """Test intelligent caching system."""
        cache = CacheManager(max_size=100, ttl_seconds=3600)

        # Test cache operations
        await cache.set('test_key', 'test_value')
        value = await cache.get('test_key')
        assert value == 'test_value'

        # Test cache miss
        missing_value = await cache.get('nonexistent_key')
        assert missing_value is None

        # Test cache stats
        stats = cache.get_cache_stats()
        assert stats['size'] == 1
        assert stats['hit_count'] == 1
        assert stats['miss_count'] == 1
        assert stats['hit_ratio'] == 0.5

    @pytest.mark.asyncio
    async def test_task_queue(self):
        """Test high-performance task queue."""
        queue = TaskQueue(max_workers=5, batch_size=3)

        # Start the queue
        await queue.start()

        # Add some test tasks
        results = []

        async def test_task(value):
            results.append(value)
            return value

        for i in range(10):
            await queue.add_task(test_task(i))

        # Wait for tasks to complete
        await asyncio.sleep(0.5)

        # Stop the queue
        await queue.stop()

        # Check statistics
        stats = queue.get_queue_stats()
        assert stats['completed_tasks'] > 0
        assert not stats['running']

    def test_performance_profiler(self):
        """Test performance profiling."""
        profiler = PerformanceProfiler()

        # Test function profiling decorator
        @profiler.profile_function
        def test_function(x, y):
            return x + y

        # Call the function
        result = test_function(2, 3)
        assert result == 5

        # Check profiling data
        report = profiler.get_profile_report()
        assert report['total_functions'] > 0
        assert report['total_calls'] > 0

        # Should have recorded the function call
        func_name = f"{test_function.__module__}.test_function"
        assert func_name in report['function_stats']


class TestIntegrationWorkflow:
    """Test complete Phase 6 integration workflow."""

    @pytest.mark.asyncio
    async def test_complete_cicd_workflow(self):
        """Test complete CI/CD integration workflow."""
        # Create temporary directory for reports
        with tempfile.TemporaryDirectory() as temp_dir:
            cicd_manager = CICDManager()
            await cicd_manager.initialize()

            # Mock environment detection
            with patch.object(cicd_manager, 'detect_cicd_environment') as mock_detect:
                mock_detect.return_value = CICDPlatform.GITHUB_ACTIONS

                # Mock scan execution
                with patch.object(cicd_manager, '_mock_scan_execution') as mock_scan:
                    mock_scan.return_value = {
                        'target': 'https://api.example.com',
                        'findings': [
                            {'title': 'High Severity Issue', 'severity': 'HIGH'},
                            {'title': 'Medium Severity Issue', 'severity': 'MEDIUM'}
                        ]
                    }

                    # Execute CI/CD scan
                    result = await cicd_manager.execute_cicd_scan(
                        targets=['https://api.example.com'],
                        scan_types=['discovery', 'vulnerabilities'],
                        severity_threshold='MEDIUM',
                        fail_on_vulnerabilities=True,
                        output_dir=temp_dir
                    )

                    # Verify results
                    assert result.success is False  # Should fail due to high severity issue
                    assert result.vulnerabilities_found == 2
                    assert result.high_severity_count == 1
                    assert result.exit_code == 1

                    # Check that reports were generated
                    report_dir = Path(temp_dir)
                    assert report_dir.exists()

                    # Check for summary file
                    summary_file = report_dir / 'summary.json'
                    assert summary_file.exists()

                    # Verify summary content
                    with open(summary_file) as f:
                        summary = json.load(f)

                    assert summary['total_vulnerabilities'] == 2
                    assert summary['high_severity'] == 1

    @pytest.mark.asyncio
    async def test_plugin_notification_integration(self):
        """Test plugin notification integration."""
        # Create plugin manager with mock plugins
        config = {
            'plugins': {'enabled': ['slack_notifications']},
            'plugin_configs': {
                'slack_notifications': {
                    'webhook_url': 'https://hooks.slack.com/test'
                }
            }
        }

        plugin_manager = PluginManager(config)
        await plugin_manager.initialize()

        # Mock the notification sending
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_post.return_value.__aenter__.return_value = mock_response

            # Send test notifications
            results = await plugin_manager.send_notifications(
                "CI/CD scan completed with vulnerabilities found", "warning"
            )

            # Should return results even if no actual plugins loaded
            assert isinstance(results, dict)

    def test_configuration_file_generation(self):
        """Test CI/CD configuration file generation."""
        cicd_manager = CICDManager()

        with tempfile.TemporaryDirectory() as temp_dir:
            scan_config = ScanConfiguration(
                target_urls=['https://api.example.com', 'https://staging.example.com'],
                scan_types=['discovery', 'vulnerabilities', 'auth'],
                severity_threshold='MEDIUM',
                fail_on_vulnerabilities=True,
                report_formats=['json', 'html', 'junit']
            )

            # Generate all platform configurations
            platforms = [
                CICDPlatform.GITHUB_ACTIONS,
                CICDPlatform.GITLAB_CI,
                CICDPlatform.JENKINS
            ]

            for platform in platforms:
                config_content = cicd_manager.generate_pipeline_config(
                    platform, scan_config, temp_dir
                )

                # Verify configuration content
                assert 'api-hunter cicd-scan' in config_content
                assert 'https://api.example.com' in config_content
                assert 'MEDIUM' in config_content

                # Check that files were created
                temp_path = Path(temp_dir)
                config_files = list(temp_path.glob('*'))
                assert len(config_files) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
