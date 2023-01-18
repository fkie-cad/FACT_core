from __future__ import annotations

import ctypes

import numpy as np

from analysis.PluginBase import AnalysisBasePlugin


def get_plugin_stats(plugin: AnalysisBasePlugin) -> dict[str, str] | None:
    try:
        stats_count = plugin.analysis_stats_count.value
        stats_array = np.array(plugin.analysis_stats.get_obj(), ctypes.c_float)
        if stats_count < plugin.ANALYSIS_STATS_LIMIT:
            stats_array = stats_array[:stats_count]
        return dict(
            min=_format_float(stats_array.min()),
            max=_format_float(stats_array.max()),
            mean=_format_float(stats_array.mean()),
            median=_format_float(np.median(stats_array)),
            std_dev=_format_float(stats_array.std()),
            count=str(stats_count),
        )
    except (ValueError, AssertionError):
        return None


def _format_float(number: float) -> str:
    """format float with 2 decimal places"""
    return f'{number:.2f}'
