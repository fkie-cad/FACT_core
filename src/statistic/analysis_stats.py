from __future__ import annotations

import statistics

from analysis.PluginBase import AnalysisBasePlugin


def get_plugin_stats(plugin: AnalysisBasePlugin) -> dict[str, str] | None:
    try:
        return dict(
            min=_format_float(min(plugin.analysis_stats)),
            max=_format_float(max(plugin.analysis_stats)),
            mean=_format_float(statistics.mean(plugin.analysis_stats)),
            median=_format_float(statistics.median(plugin.analysis_stats)),
            variance=_format_float(statistics.variance(plugin.analysis_stats)),
            count=str(len(plugin.analysis_stats)),
        )
    except (ValueError, AssertionError):
        return None


def _format_float(number: float) -> str:
    """format float with 2 decimal places"""
    return f'{number:.2f}'
