from typing import Any

import pytest
from flask import render_template_string

from version import __VERSION__


def test_auth_is_disabled(web_frontend):
    _assert_is_rendered(web_frontend, 'auth_is_enabled', False)


@pytest.mark.frontend_config_overwrite({'authentication': {'enabled': True}})
def test_auth_is_enabled(web_frontend):
    _assert_is_rendered(web_frontend, 'auth_is_enabled', True)


def test_get_fact_version(web_frontend):
    _assert_is_rendered(web_frontend, 'get_fact_version', __VERSION__)


def _assert_is_rendered(web_frontend, function: str, expected_value: Any):
    with web_frontend.app.test_request_context():
        template = render_template_string(f'<html><body><div>{{{{ {function}() }}}}</div></body></html>')
        assert f'<div>{expected_value}</div>' in template
