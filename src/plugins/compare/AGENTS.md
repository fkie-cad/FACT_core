# Comparison Plugins

Each plugin is a package `<name>/` with `code/<name>.py` defining `class ComparePlugin(CompareBasePlugin)`
(`src/compare/PluginBase.py`). Comparison plugins run on a list of firmware objects (`fo_list`), not on single files.

- Set `FILE = __file__`, `NAME` and `DEPENDENCIES` (analysis plugins whose results must be present in every
  `fo.processed_analysis`; otherwise the comparison is skipped).
- `COMPARISON_DEPS`: comparison plugins that must run first; their results arrive in `dependency_results`.
- Implement `compare_function(fo_list, dependency_results) -> dict[str, dict]`.
  Result format: `{'<label>': {'all': <value>, '<uid>': <value>, ..., 'collapse': bool}}`
  (`all` = shared by all firmwares, per-uid keys = differences).
- Optional `view/` template; without one a generic view is used. Example: `software/`.
