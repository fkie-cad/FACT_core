# Storage

- PostgreSQL (SQLAlchemy, models in `schema.py`): file objects, firmware metadata, analysis results (JSONB),
  comparisons, stats. Access goes through the `db_interface_*.py` classes, which use separate DB roles
  (read-only / read-write / delete / admin) — use the least privileged interface that works.
  The backend mainly writes, the frontend mainly reads.
- File binaries are not in the DB but in the file storage directory (`file_service.py`).
- Redis (`redis_*.py`) is only used for intercom and transient status, never for persistent data.
- GraphQL via Hasura (`graphql/`) exposes the PostgreSQL schema to the frontend.

## Schema changes

Every change to `schema.py` needs an Alembic migration in `migration/versions/`
(`alembic revision -m "<message>"`, run from `src/`). Components refuse to start if the DB revision
is not at head. Tests create their tables directly from `schema.py`, so they will not catch a missing migration.
