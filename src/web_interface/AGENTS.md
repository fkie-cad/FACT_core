# Web Interface

- Routes: `ComponentBase` subclasses in `components/`, methods decorated with `@AppRoute(path, GET/POST)`.
  REST API: flask-restx resources in `rest/` (Swagger UI at `/doc/`). Templates: Jinja2 in `templates/`.
- Access control: every route needs `@roles_accepted(*PRIVILEGES['<privilege>'])`
  (`security/decorator.py`, privileges in `security/privileges.py`), placed above `@AppRoute` / on the REST method.
  Without it the route is public. Use `@roles_accepted(no_role_needed=True)` only for intentionally public pages
  and add them to `NO_AUTH_ENDPOINTS` in `src/test/acceptance/test_authenticated_gui.py`.
  That acceptance test catches routes without login requirement, but not a wrong privilege — choose it carefully.
- Users and roles are stored in a separate SQLite DB (`[frontend.authentication]`), managed with `src/manage_users.py`.
- Statistics: unfiltered stats are precomputed and read from the DB (updated by `src/update_statistic.py`,
  logic in `src/statistic/update.py`); filtered stats are computed live.
- Unit tests use the `web_frontend` / `test_client` fixtures with mocked DB and intercom (see `src/test/AGENTS.md`).
