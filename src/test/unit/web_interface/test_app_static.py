import re
from pathlib import Path

import pytest
from flask import url_for

URL_FOR_REGEX = re.compile(r'url_for\([\'"]\.?static[\'"], filename ?= ?[\'"]([^\'"]+)[\'"]\)')
TEMPLATE_DIR = Path(__file__).parent.parent.parent.parent / 'web_interface/templates'


def _find_static_files():
    return {
        (template, static_url)
        for template in TEMPLATE_DIR.glob('**/*.html')
        for static_url in URL_FOR_REGEX.findall(template.read_text())
    }


@pytest.mark.parametrize(('template', 'static_file'), list(_find_static_files()))
def test_add_firmwares_to_compare__multiple(web_frontend, test_client, template, static_file):
    with web_frontend.app.test_request_context():
        url = url_for('static', filename=static_file)
        rv = test_client.get(url, follow_redirects=True)
        assert rv.status == '200 OK', f'static file {static_file} from {template} not found!'
