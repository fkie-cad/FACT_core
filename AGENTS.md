# AGENTS.md

FACT (Firmware Analysis and Comparison Tool): firmware unpacking and analysis backend,
Flask web UI + REST API. Backend, frontend and database run as separate processes
(`src/start_fact_*.py`) and communicate via Redis (`src/intercom/`). Analysis results and metadata
of unpacked files are stored in PostgreSQL (`src/storage/`), file binaries in the file storage directory.
Unpacking itself is done by the separate fact_extractor project (Docker); unpacking plugins are not in this repo.

- FACT is already installed. Don't install or start it; verify changes with tests.
- Always use FACT's venv (ask for the path if unknown): activate it or put `<venv>/bin` on `PATH` in the same
  shell command. Calling only `<venv>/bin/python -m pytest …` is not enough: some tests start scripts via their
  shebang or call venv tools by name and would pick up the system Python.
- Code must support the minimum Python version (`target-version` in `pyproject.toml`).
- Tests: run only the relevant ones. They need PostgreSQL db `fact_test` and Redis db 13.
  Tests never use the real config: `src/conftest.py` patches it. Override values with the markers
  `common_config_overwrite` / `backend_config_overwrite` / `frontend_config_overwrite`; don't monkeypatch `config`.
- Lint the files you changed: `ruff check --fix <files>` and `ruff format <files>`. The pre-commit hook checks
  whole files, so existing findings in a file you touch must be fixed too; don't touch files you don't otherwise change.
- Config: `src/config/fact-core-config.toml`.
- If your change makes a statement in an `AGENTS.md` wrong (moved/renamed files or classes, changed
  conventions, config keys, fixtures), update that statement in the same change. Don't add new content unasked.
- New analysis plugin: first read `src/plugins/analysis/example_plugin/`.
  New compare plugin: first read an existing one in `src/plugins/compare/`.
