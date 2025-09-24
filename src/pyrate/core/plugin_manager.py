"""
Plugin management system for Pyrate vulnerability scanner.
"""

import importlib.util
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
import sys

from .config import Config
from ..models.plugin import BasePlugin

logger = logging.getLogger(__name__)


class PluginManager:
    """Manages loading and execution of vulnerability scanning plugins."""
    
    def __init__(self, config: Config):
        """
        Initialize the plugin manager.
        
        Args:
            config: Configuration instance
        """
        self.config = config
        self._plugins: Dict[str, BasePlugin] = {}
        self._load_plugins()
    
    def _load_plugins(self) -> None:
        """Load all available plugins from plugin directories."""
        logger.info("Loading plugins...")
        
        # Load built-in plugins
        self._load_builtin_plugins()
        
        # Load plugins from configured directories
        for plugin_dir in self.config.plugins.plugin_directories:
            if plugin_dir.exists() and plugin_dir.is_dir():
                self._load_plugins_from_directory(plugin_dir)
        
        logger.info(f"Loaded {len(self._plugins)} plugins")
    
    def _load_builtin_plugins(self) -> None:
        """Load built-in plugins from the plugins package."""
        try:
            from ..plugins import builtin_plugins
            
            for plugin_class in builtin_plugins.get_all_plugins():
                try:
                    plugin_instance = plugin_class()
                    self._plugins[plugin_instance.name] = plugin_instance
                    logger.debug(f"Loaded built-in plugin: {plugin_instance.name}")
                except Exception as e:
                    logger.error(f"Failed to load built-in plugin {plugin_class.__name__}: {e}")
                    
        except ImportError:
            logger.warning("No built-in plugins found")
    
    def _load_plugins_from_directory(self, plugin_dir: Path) -> None:
        """
        Load plugins from a specific directory.
        
        Args:
            plugin_dir: Directory containing plugin files
        """
        logger.debug(f"Loading plugins from directory: {plugin_dir}")
        
        # Add plugin directory to Python path
        if str(plugin_dir) not in sys.path:
            sys.path.insert(0, str(plugin_dir))
        
        # Find all Python files in the plugin directory
        for plugin_file in plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("__"):
                continue
                
            try:
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Look for plugin classes in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, BasePlugin) and 
                            attr != BasePlugin):
                            
                            try:
                                plugin_instance = attr()
                                self._plugins[plugin_instance.name] = plugin_instance
                                logger.debug(f"Loaded plugin: {plugin_instance.name}")
                            except Exception as e:
                                logger.error(f"Failed to instantiate plugin {attr_name}: {e}")
                                
            except Exception as e:
                logger.error(f"Failed to load plugin from {plugin_file}: {e}")
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """
        Get a specific plugin by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin instance or None if not found
        """
        return self._plugins.get(name)
    
    def list_plugins(self) -> List[BasePlugin]:
        """
        Get list of all available plugins.
        
        Returns:
            List of plugin instances
        """
        return list(self._plugins.values())
    
    def get_active_plugins(self, requested_plugins: Optional[List[str]] = None) -> List[BasePlugin]:
        """
        Get list of active plugins based on configuration and request.
        
        Args:
            requested_plugins: Specific plugins requested (None for all enabled)
            
        Returns:
            List of active plugin instances
        """
        if requested_plugins:
            # Return specific requested plugins
            active_plugins = []
            for plugin_name in requested_plugins:
                plugin = self.get_plugin(plugin_name)
                if plugin:
                    if plugin_name not in self.config.plugins.disabled_plugins:
                        active_plugins.append(plugin)
                    else:
                        logger.warning(f"Plugin {plugin_name} is disabled in configuration")
                else:
                    logger.warning(f"Requested plugin {plugin_name} not found")
            return active_plugins
        
        # Return all enabled plugins
        active_plugins = []
        for plugin in self._plugins.values():
            # Check if plugin is explicitly enabled or not explicitly disabled
            if self.config.plugins.enabled_plugins:
                # If enabled_plugins list is specified, only include those
                if plugin.name in self.config.plugins.enabled_plugins:
                    if plugin.name not in self.config.plugins.disabled_plugins:
                        active_plugins.append(plugin)
            else:
                # If no enabled_plugins list, include all except disabled
                if plugin.name not in self.config.plugins.disabled_plugins:
                    active_plugins.append(plugin)
        
        return active_plugins
    
    def reload_plugins(self) -> None:
        """Reload all plugins from directories."""
        self._plugins.clear()
        self._load_plugins()
    
    def get_plugins_by_category(self, category: str) -> List[BasePlugin]:
        """
        Get plugins filtered by category.
        
        Args:
            category: Plugin category to filter by
            
        Returns:
            List of plugins in the specified category
        """
        return [plugin for plugin in self._plugins.values() 
                if plugin.category.lower() == category.lower()]
    
    def get_plugins_by_risk_level(self, risk_level: str) -> List[BasePlugin]:
        """
        Get plugins filtered by risk level.
        
        Args:
            risk_level: Risk level to filter by (LOW, MEDIUM, HIGH)
            
        Returns:
            List of plugins with the specified risk level
        """
        return [plugin for plugin in self._plugins.values() 
                if plugin.risk_level.upper() == risk_level.upper()]