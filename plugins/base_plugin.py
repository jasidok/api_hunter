"""
Base Plugin Class for API Hunter

All plugins must inherit from this base class and implement the required methods.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class PluginType(Enum):
    """Plugin types supported by API Hunter."""
    INTEGRATION = "integration"  # External tool integrations
    NOTIFICATION = "notification"  # Notification services
    EXPORT = "export"  # Data export formats
    ANALYSIS = "analysis"  # Analysis enhancements
    WORDLIST = "wordlist"  # Wordlist providers


@dataclass
class PluginInfo:
    """Plugin metadata."""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    dependencies: List[str] = None
    config_schema: Dict[str, Any] = None
    enabled: bool = True

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.config_schema is None:
            self.config_schema = {}


class BasePlugin(ABC):
    """
    Abstract base class for all API Hunter plugins.
    
    Plugins extend API Hunter's functionality by integrating with external
    tools, services, or providing additional analysis capabilities.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the plugin.
        
        Args:
            config: Plugin-specific configuration
        """
        self.config = config or {}
        self._enabled = True
        self._initialized = False

    @property
    @abstractmethod
    def plugin_info(self) -> PluginInfo:
        """Return plugin metadata."""
        pass

    @abstractmethod
    async def initialize(self) -> bool:
        """
        Initialize the plugin.
        
        Returns:
            True if initialization successful, False otherwise
        """
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up plugin resources."""
        pass

    def is_enabled(self) -> bool:
        """Check if plugin is enabled."""
        return self._enabled

    def enable(self) -> None:
        """Enable the plugin."""
        self._enabled = True

    def disable(self) -> None:
        """Disable the plugin."""
        self._enabled = False

    def is_initialized(self) -> bool:
        """Check if plugin is initialized."""
        return self._initialized

    async def validate_config(self) -> List[str]:
        """
        Validate plugin configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        if not self.plugin_info.config_schema:
            return errors

        # Basic validation - can be extended
        for required_key in self.plugin_info.config_schema.get('required', []):
            if required_key not in self.config:
                errors.append(f"Missing required configuration: {required_key}")

        return errors

    async def get_status(self) -> Dict[str, Any]:
        """
        Get plugin status information.
        
        Returns:
            Dictionary containing plugin status
        """
        return {
            'name': self.plugin_info.name,
            'version': self.plugin_info.version,
            'type': self.plugin_info.plugin_type.value,
            'enabled': self.is_enabled(),
            'initialized': self.is_initialized(),
            'config_valid': len(await self.validate_config()) == 0
        }


class IntegrationPlugin(BasePlugin):
    """Base class for external tool integration plugins."""

    @abstractmethod
    async def send_findings(self, findings: List[Dict[str, Any]]) -> bool:
        """
        Send vulnerability findings to external tool.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def import_data(self) -> List[Dict[str, Any]]:
        """
        Import data from external tool.
        
        Returns:
            List of imported data items
        """
        pass


class NotificationPlugin(BasePlugin):
    """Base class for notification plugins."""

    @abstractmethod
    async def send_notification(self, message: str, severity: str = "info") -> bool:
        """
        Send a notification.
        
        Args:
            message: Notification message
            severity: Message severity (info, warning, error, critical)
            
        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def send_report(self, report_data: Dict[str, Any]) -> bool:
        """
        Send a scan report.
        
        Args:
            report_data: Report data to send
            
        Returns:
            True if successful, False otherwise
        """
        pass


class ExportPlugin(BasePlugin):
    """Base class for export format plugins."""

    @abstractmethod
    async def export_findings(self, findings: List[Dict[str, Any]],
                              output_path: str) -> bool:
        """
        Export findings to specified format.
        
        Args:
            findings: List of vulnerability findings
            output_path: Output file path
            
        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def get_file_extension(self) -> str:
        """
        Get the file extension for this export format.
        
        Returns:
            File extension (e.g., '.csv', '.xlsx')
        """
        pass
