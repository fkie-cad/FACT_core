from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from analysis.PluginBase import AnalysisBasePlugin

if TYPE_CHECKING:
    from analysis.plugin import AnalysisPluginV0


def check_plugin_blacklists(analysis_plugins: dict[str, AnalysisPluginV0 | AnalysisBasePlugin]):
    """
    Check if there are cases where the analysis of a supported file type is not allowed for a dependency:
    If plugin A depends on B and allows the analysis of file type X and this type is blacklisted for dependency B,
    then the analysis of plugin A will always be skipped (which does not make a lot of sense, so we want to find
    such cases and warn the user).
    """
    for plugin_name, plugin in analysis_plugins.items():
        dependencies = _get_recursive_dependencies(plugin_name, analysis_plugins)
        blacklist = _get_blacklist(plugin)
        whitelist = _get_whitelist(plugin)
        for dependency_name in dependencies:
            dependency = analysis_plugins.get(dependency_name)
            if not dependency:
                logging.warning(f'Dependency {dependency_name} of plugin {plugin_name} is missing.')
                continue
            dependency_blacklist = _get_blacklist(dependency)
            dependency_whitelist = _get_whitelist(dependency)
            type_list = set()
            if difference := dependency_blacklist.difference(blacklist):
                # the blacklist of the plugin should be at least as restrictive as those of the dependencies
                type_list.update(difference)
            if dependency_whitelist and (difference := whitelist.difference(dependency_whitelist)):
                # the whitelist of the plugin should be at least as restrictive as those of the dependencies
                type_list.update(difference)
            if union := whitelist.intersection(dependency_blacklist):
                # whitelisted types should not be blacklisted by dependencies
                type_list.update(union)
            if type_list:
                logging.warning(
                    f'Plugin {plugin_name} allows analysis of types {type_list} which are either blacklisted or '
                    f'not whitelisted for dependency {dependency_name}. These analyses will always be skipped!'
                )


def _get_recursive_dependencies(
    plugin_name: str, analysis_plugins: dict[str, AnalysisPluginV0 | AnalysisBasePlugin]
) -> set[str]:
    plugin = analysis_plugins.get(plugin_name)
    dependencies = _get_dependencies(plugin)
    for dependency in list(dependencies):
        dependencies.update(_get_recursive_dependencies(dependency, analysis_plugins))
    return dependencies


# FIXME: simplify when old base class gets removed
def _get_dependencies(plugin: AnalysisBasePlugin | AnalysisPluginV0) -> set[str]:
    return set(plugin.DEPENDENCIES if isinstance(plugin, AnalysisBasePlugin) else plugin.metadata.dependencies)


def _get_blacklist(plugin: AnalysisBasePlugin | AnalysisPluginV0) -> set[str]:
    return set(plugin.MIME_BLACKLIST if isinstance(plugin, AnalysisBasePlugin) else plugin.metadata.mime_blacklist)


def _get_whitelist(plugin: AnalysisBasePlugin | AnalysisPluginV0) -> set[str]:
    return set(plugin.MIME_WHITELIST if isinstance(plugin, AnalysisBasePlugin) else plugin.metadata.mime_whitelist)
