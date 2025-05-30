"""
API Hunter Plugin System

This module provides the plugin architecture for API Hunter, allowing
for extensible integrations with external tools and services.
"""

from .plugin_manager import PluginManager
from .base_plugin import BasePlugin

__all__ = ['PluginManager', 'BasePlugin']
