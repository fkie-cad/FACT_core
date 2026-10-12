# Analysis Plugins

Each plugin is a package `<name>/` with `code/<name>.py` defining `class AnalysisPlugin(AnalysisPluginV0)`
(`src/analysis/plugin/plugin.py`). Optional subdirectories: `test/`, `view/` (Jinja2 template for the result),
`routes/` (custom frontend routes), `internal/` (helper code), `install.py` (dependencies, run by `src/install.py`).

## How plugins are run

- A plugin only sees a single file (firmware image or unpacked file), never the whole firmware.
  Results of other plugins for the same file are only available via `dependencies`.
- `file_type` and `file_hashes` are mandatory and run first on every file; the mime filters use the
  `file_type` result. If a dependency failed or was skipped, the dependent plugin is skipped as well.
- Results are cached per file (uid = hash). A plugin only runs again on a file if its `version` or
  `system_version` is newer than the stored result, a dependency result is newer, the stored result failed,
  or the user forced an update.

## Writing a plugin

- `__init__` passes `AnalysisPluginV0.MetaData(...)` to `super().__init__(metadata=...)`:
  `name`, `description`, `version`, `Schema`, optional `dependencies`, `mime_blacklist` / `mime_whitelist`,
  `timeout` (default 300 s), `system_version` (version of the backing tool).
- `Schema` is a pydantic model; give every field a `description`.
- `analyze(file_handle, virtual_file_path, analyses) -> Schema` does the work. `analyses` contains the results
  of the plugins listed in `dependencies` (they are guaranteed to run first).
- `summarize(result) -> list[str]` (optional) returns categories used to group files in the frontend.
- Raise `AnalysisFailedError` when the analysis can't be done (missing requirement, incompatible input).
  It is logged without traceback; any other exception is treated as a bug.
- Version (semver): MAJOR = schema changed, MINOR = same schema but more data, PATCH = bugfix.
  Because of the caching above, bump it whenever results change, otherwise old results are kept.
- Per-plugin settings (e.g. `processes`) go in `[[backend.plugin]]` in `src/config/fact-core-config.toml`.

## Testing

Use the `analysis_plugin` fixture (`src/conftest.py`) and select the class with a marker:

```python
@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_something(analysis_plugin):
    result = analysis_plugin.analyze(file_handle, {}, {})
```
