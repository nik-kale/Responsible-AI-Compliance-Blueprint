"""Plugin system for custom compliance checks."""

from pathlib import Path
from typing import List, Protocol, runtime_checkable
import importlib.util
import sys

from ..config.schema import ProjectConfig, Finding
from .logger import get_logger

logger = get_logger(__name__)


@runtime_checkable
class ComplianceCheckPlugin(Protocol):
    """Protocol for compliance check plugins."""

    name: str
    version: str

    def run_checks(self, config: ProjectConfig, project_root: Path, env: str) -> List[Finding]:
        """
        Run compliance checks.

        Args:
            config: Project configuration
            project_root: Project root directory
            env: Environment name

        Returns:
            List of findings
        """
        ...


class PluginManager:
    """Manage compliance check plugins."""

    def __init__(self, plugin_dir: Path = None):
        """
        Initialize plugin manager.

        Args:
            plugin_dir: Directory containing plugin files (default: ./plugins)
        """
        self.plugin_dir = plugin_dir or Path.cwd() / "plugins"
        self.plugins: List[ComplianceCheckPlugin] = []

    def discover_plugins(self) -> int:
        """
        Discover and load plugins from plugin directory.

        Returns:
            Number of plugins loaded
        """
        if not self.plugin_dir.exists():
            logger.info(f"Plugin directory does not exist: {self.plugin_dir}")
            return 0

        loaded_count = 0

        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue  # Skip private files

            try:
                plugin = self._load_plugin(plugin_file)
                if plugin:
                    self.plugins.append(plugin)
                    loaded_count += 1
                    logger.info(f"Loaded plugin: {plugin.name} v{plugin.version}")
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file}: {e}")

        return loaded_count

    def _load_plugin(self, plugin_path: Path) -> ComplianceCheckPlugin:
        """
        Load a single plugin from file.

        Args:
            plugin_path: Path to plugin file

        Returns:
            Plugin instance or None if loading failed
        """
        # Security: Validate plugin path is within plugin directory
        try:
            resolved_plugin = plugin_path.resolve()
            resolved_dir = self.plugin_dir.resolve()

            # Ensure plugin is actually within the plugin directory
            resolved_plugin.relative_to(resolved_dir)
        except (ValueError, RuntimeError) as e:
            logger.error(f"Security: Plugin path outside plugin directory: {plugin_path}")
            return None

        module_name = f"raicb_plugin_{plugin_path.stem}"

        # Load module from file
        spec = importlib.util.spec_from_file_location(module_name, resolved_plugin)
        if not spec or not spec.loader:
            logger.error(f"Failed to load spec for {plugin_path}")
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        # Look for Plugin class
        if not hasattr(module, "Plugin"):
            logger.error(f"Plugin file {plugin_path} does not define 'Plugin' class")
            return None

        plugin_class = module.Plugin
        plugin = plugin_class()

        # Validate plugin implements protocol
        if not isinstance(plugin, ComplianceCheckPlugin):
            logger.error(f"Plugin {plugin_path} does not implement ComplianceCheckPlugin protocol")
            return None

        return plugin

    def run_all_plugins(
        self, config: ProjectConfig, project_root: Path, env: str
    ) -> List[Finding]:
        """
        Run all loaded plugins.

        Args:
            config: Project configuration
            project_root: Project root directory
            env: Environment name

        Returns:
            Combined list of findings from all plugins
        """
        all_findings = []

        for plugin in self.plugins:
            try:
                logger.info(f"Running plugin: {plugin.name}")
                findings = plugin.run_checks(config, project_root, env)
                all_findings.extend(findings)
                logger.info(f"Plugin {plugin.name} returned {len(findings)} findings")
            except Exception as e:
                logger.error(f"Error running plugin {plugin.name}: {e}", exc_info=True)

                # Create error finding
                from ..config.schema import Finding, Severity, Status

                all_findings.append(
                    Finding(
                        check_id=f"PLUGIN-ERROR-{plugin.name}",
                        title=f"Plugin Error: {plugin.name}",
                        severity=Severity.HIGH,
                        status=Status.ERROR,
                        category="plugin",
                        description=f"Error executing plugin: {plugin.name}",
                        evidence=f"Exception: {type(e).__name__}: {str(e)}",
                        remediation="Check plugin implementation and logs",
                        owasp_mapping=[],
                        iso_mapping=[],
                    )
                )

        return all_findings

    def get_plugins(self) -> List[ComplianceCheckPlugin]:
        """
        Get all loaded plugin instances.

        Returns:
            List of plugin instances
        """
        return self.plugins

    def list_plugins(self) -> List[dict]:
        """
        List all loaded plugins.

        Returns:
            List of plugin information dictionaries
        """
        return [{"name": p.name, "version": p.version} for p in self.plugins]
