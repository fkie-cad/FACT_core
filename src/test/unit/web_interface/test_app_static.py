from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import pytest
from flask import url_for

from helperFunctions.fileSystem import get_src_dir, get_template_dir

URL_FOR_REGEX = re.compile(r'url_for\([\'"]\.?static[\'"], filename ?= ?[\'"]([^\'"]+)[\'"]\)')
SRC_DIR = Path(get_src_dir())


def _find_static_files() -> Iterable[tuple[str, set[str]]]:
    result = {}
    for template in get_template_dir().glob('**/*.html'):
        for static_url in URL_FOR_REGEX.findall(template.read_text()):
            result.setdefault(static_url, set()).add(str(template.relative_to(SRC_DIR)))
    return result.items()


@pytest.mark.parametrize(('static_file', 'template'), _find_static_files())
def test_static_web_files_are_found(web_frontend, test_client, template, static_file):
    with web_frontend.app.test_request_context():
        url = url_for('static', filename=static_file)
        rv = test_client.get(url, follow_redirects=True)
        assert rv.status == '200 OK', f'static file {static_file} from {template} not found!'
