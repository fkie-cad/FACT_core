# Tests

- `unit/`: no DB needed (DB and intercom are mocked). `integration/` and `acceptance/`: use the real test DB
  (`fact_test`), which is emptied after every test.
- Config is always the test config from `src/conftest.py`. Override values with
  `@pytest.mark.common_config_overwrite({...})`, `backend_config_overwrite`, `frontend_config_overwrite`.
  Markers on module, class and function level are merged (closest wins).
- `OSError: Too many open files` when running many tests: raise the limit (`ulimit -n`) in the same shell command.

## Fixtures (configured via markers of the same name as their config class)

| Fixture | Defined in | Marker / config class |
|---|---|---|
| `analysis_plugin` | `src/conftest.py` | `AnalysisPluginTestConfig(plugin_class=...)` |
| `web_frontend`, `test_client` | `unit/conftest.py` | `WebInterfaceUnitTestConfig` (DB / intercom / status mock classes) |
| `analysis_scheduler`, `unpacking_scheduler`, `comparison_scheduler` | `conftest.py` | `SchedulerTestConfig` (DB / file service / view updater classes, start processes, pipeline) |
| `database_interfaces`, `backend_db`, `frontend_db`, … | `conftest.py` | — (real test DB) |

See the docstrings of the config classes for all options; reuse the existing mocks in `unit/conftest.py`
and `src/test/common_helper.py` instead of writing new ones.
