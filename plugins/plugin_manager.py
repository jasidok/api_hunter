"""
Plugin Manager for API Hunter

Handles loading, managing, and coordinating plugins.
"""

import os
import sys
import importlib
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Type, Any
from dataclasses import dataclass, field

from .base_plugin import BasePlugin, PluginType, PluginInfo


@dataclass
class PluginRegistry:
    """Registry for tracking loaded plugins."""
    plugins: Dict[str, BasePlugin] = field(default_factory=dict)
    plugin_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    enabled_plugins: Dict[str, bool] = field(default_factory=dict)


class PluginManager:
    """
    Manages the lifecycle and coordination of API Hunter plugins.
    
    Handles plugin discovery, loading, initialization, and cleanup.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the plugin manager.
        
        Args:
            config: Global configuration including plugin settings
        """
        self.config = config or {}
        self.registry = PluginRegistry()
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the plugin manager and load plugins."""
        if self._initialized:
            return

        # Load built-in plugins
        await self._load_builtin_plugins()

        # Load external plugins
        await self._load_external_plugins()

        # Initialize enabled plugins
        await self._initialize_plugins()

        self._initialized = True

    async def cleanup(self) -> None:
        """Clean up all plugins and resources."""
        for plugin in self.registry.plugins.values():
            try:
                await plugin.cleanup()
            except Exception as e:
                print(f"Error cleaning up plugin {plugin.plugin_info.name}: {e}")

        self.registry.plugins.clear()
        self._initialized = False

    async def _load_builtin_plugins(self) -> None:
        """Load built-in plugins from the plugins directory."""
        builtin_dir = Path(__file__).parent / "builtin"
        if not builtin_dir.exists():
            return

        for plugin_file in builtin_dir.glob("*.py"):
            if plugin_file.name.startswith("__"):
                continue

            try:
                await self._load_plugin_from_file(plugin_file)
            except Exception as e:
                print(f"Error loading builtin plugin {plugin_file.name}: {e}")

    async def _load_external_plugins(self) -> None:
        """Load external plugins from configured directories."""
        plugin_dirs = self.config.get('plugin_directories', [])

        for plugin_dir in plugin_dirs:
            plugin_path = Path(plugin_dir)
            if not plugin_path.exists():
                continue

            for plugin_file in plugin_path.glob("*.py"):
                if plugin_file.name.startswith("__"):
                    continue

                try:
                    await self._load_plugin_from_file(plugin_file)
                except Exception as e:
                    print(f"Error loading external plugin {plugin_file.name}: {e}")

    async def _load_plugin_from_file(self, plugin_file: Path) -> None:
        """
        Load a plugin from a Python file.
        
        Args:
            plugin_file: Path to the plugin file
        """
        module_name = plugin_file.stem
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
        if not spec or not spec.loader:
            return

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Look for plugin classes in the module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) and
                    issubclass(attr, BasePlugin) and
                    attr != BasePlugin):

                # Create plugin instance
                plugin_config = self._get_plugin_config(attr_name)
                plugin_instance = attr(plugin_config)

                # Register the plugin
                self.registry.plugins[attr_name] = plugin_instance
                self.registry.plugin_configs[attr_name] = plugin_config

                # Check if plugin should be enabled
                enabled = self.config.get('plugins', {}).get('enabled', [])
                disabled = self.config.get('plugins', {}).get('disabled', [])

                if attr_name in disabled:
                    self.registry.enabled_plugins[attr_name] = False
                    plugin_instance.disable()
                elif attr_name in enabled or not enabled:  # Enable by default if no enabled list
                    self.registry.enabled_plugins[attr_name] = True
                else:
                    self.registry.enabled_plugins[attr_name] = False
                    plugin_instance.disable()

    def _get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin-specific configuration
        """
        return self.config.get('plugin_configs', {}).get(plugin_name, {})

    async def _initialize_plugins(self) -> None:
        """Initialize all enabled plugins."""
        for plugin_name, plugin in self.registry.plugins.items():
            if not plugin.is_enabled():
                continue

            try:
                success = await plugin.initialize()
                if not success:
                    print(f"Failed to initialize plugin: {plugin_name}")
                    plugin.disable()
                else:
                    plugin._initialized = True
            except Exception as e:
                print(f"Error initializing plugin {plugin_name}: {e}")
                plugin.disable()

    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """
        Get a plugin by name.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin instance or None if not found
        """
        return self.registry.plugins.get(plugin_name)

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[BasePlugin]:
        """
        Get all plugins of a specific type.
        
        Args:
            plugin_type: Type of plugins to retrieve
            
        Returns:
            List of plugins of the specified type
        """
        plugins = []
        for plugin in self.registry.plugins.values():
            if plugin.plugin_info.plugin_type == plugin_type and plugin.is_enabled():
                plugins.append(plugin)
        return plugins

    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all registered plugins with their status.
        
        Returns:
            List of plugin information dictionaries
        """
        plugin_list = []
        for plugin_name, plugin in self.registry.plugins.items():
            plugin_info = {
                'name': plugin_name,
                'version': plugin.plugin_info.version,
                'description': plugin.plugin_info.description,
                'type': plugin.plugin_info.plugin_type.value,
                'author': plugin.plugin_info.author,
                'enabled': plugin.is_enabled(),
                'initialized': plugin.is_initialized(),
                'dependencies': plugin.plugin_info.dependencies
            }
            plugin_list.append(plugin_info)
        return plugin_list

    async def enable_plugin(self, plugin_name: str) -> bool:
        """
        Enable a plugin.
        
        Args:
            plugin_name: Name of the plugin to enable
            
        Returns:
            True if successful, False otherwise
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            return False

        plugin.enable()
        self.registry.enabled_plugins[plugin_name] = True

        # Initialize if not already initialized
        if not plugin.is_initialized():
            try:
                success = await plugin.initialize()
                if success:
                    plugin._initialized = True
                return success
            except Exception as e:
                print(f"Error initializing plugin {plugin_name}: {e}")
                plugin.disable()
                return False

        return True

    async def disable_plugin(self, plugin_name: str) -> bool:
        """
        Disable a plugin.
        
        Args:
            plugin_name: Name of the plugin to disable
            
        Returns:
            True if successful, False otherwise
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            return False

        try:
            await plugin.cleanup()
        except Exception as e:
            print(f"Error cleaning up plugin {plugin_name}: {e}")

        plugin.disable()
        plugin._initialized = False
        self.registry.enabled_plugins[plugin_name] = False

        return True

    async def reload_plugin(self, plugin_name: str) -> bool:
        """
        Reload a plugin.
        
        Args:
            plugin_name: Name of the plugin to reload
            
        Returns:
            True if successful, False otherwise
        """
        if plugin_name in self.registry.plugins:
            await self.disable_plugin(plugin_name)

        # Note: Actual reloading would require more complex module reloading
        # This is a simplified version
        return await self.enable_plugin(plugin_name)

    async def send_to_integration_plugins(self, findings: List[Dict[str, Any]]) -> Dict[str, bool]:
        """
        Send findings to all enabled integration plugins.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Dictionary mapping plugin names to success status
        """
        results = {}
        integration_plugins = self.get_plugins_by_type(PluginType.INTEGRATION)

        for plugin in integration_plugins:
            try:
                from .base_plugin import IntegrationPlugin
                if isinstance(plugin, IntegrationPlugin):
                    success = await plugin.send_findings(findings)
                    results[plugin.plugin_info.name] = success
            except Exception as e:
                print(f"Error sending findings to {plugin.plugin_info.name}: {e}")
                results[plugin.plugin_info.name] = False

        return results

    async def send_notifications(self, message: str, severity: str = "info") -> Dict[str, bool]:
        """
        Send notifications to all enabled notification plugins.
        
        Args:
            message: Notification message
            severity: Message severity
            
        Returns:
            Dictionary mapping plugin names to success status
        """
        results = {}
        notification_plugins = self.get_plugins_by_type(PluginType.NOTIFICATION)

        for plugin in notification_plugins:
            try:
                from .base_plugin import NotificationPlugin
                if isinstance(plugin, NotificationPlugin):
                    success = await plugin.send_notification(message, severity)
                    results[plugin.plugin_info.name] = success
            except Exception as e:
                print(f"Error sending notification via {plugin.plugin_info.name}: {e}")
                results[plugin.plugin_info.name] = False

        return results

    async def export_findings(self, findings: List[Dict[str, Any]],
                              export_format: str, output_path: str) -> bool:
        """
        Export findings using the specified format plugin.
        
        Args:
            findings: List of vulnerability findings
            export_format: Export format name
            output_path: Output file path
            
        Returns:
            True if successful, False otherwise
        """
        export_plugins = self.get_plugins_by_type(PluginType.EXPORT)

        for plugin in export_plugins:
            if plugin.plugin_info.name.lower() == export_format.lower():
                try:
                    from .base_plugin import ExportPlugin
                    if isinstance(plugin, ExportPlugin):
                        return await plugin.export_findings(findings, output_path)
                except Exception as e:
                    print(f"Error exporting via {plugin.plugin_info.name}: {e}")
                    return False

        return False

    def get_plugin_status_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all plugin statuses.
        
        Returns:
            Summary dictionary with plugin statistics
        """
        total_plugins = len(self.registry.plugins)
        enabled_count = sum(1 for p in self.registry.plugins.values() if p.is_enabled())
        initialized_count = sum(1 for p in self.registry.plugins.values() if p.is_initialized())

        type_counts = {}
        for plugin in self.registry.plugins.values():
            ptype = plugin.plugin_info.plugin_type.value
            type_counts[ptype] = type_counts.get(ptype, 0) + 1

        return {
            'total_plugins': total_plugins,
            'enabled_plugins': enabled_count,
            'initialized_plugins': initialized_count,
            'plugins_by_type': type_counts,
            'manager_initialized': self._initialized
        }
