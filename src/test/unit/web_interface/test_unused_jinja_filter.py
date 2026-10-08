import re
from pathlib import Path

from helperFunctions.fileSystem import get_src_dir
from web_interface.components.jinja_filter import FilterClass


# mock jinja env to get filter list
class MockApp:
    class JinjaEnv:
        def __init__(self):
            self.filters = {}

        def add_extension(self, _):
            pass

    def __init__(self):
        self.jinja_env = self.JinjaEnv()


def _get_filters() -> set[str]:
    app = MockApp()
    FilterClass(app, '', None)
    return set(app.jinja_env.filters)


def test_unused_jinja_filter() -> None:
    templates_dir = Path(get_src_dir())
    assert templates_dir.is_dir(), f'{templates_dir} not found'

    search_dirs = [
        *templates_dir.glob('plugins/*/*/view'),
        templates_dir / 'web_interface' / 'templates',
    ]

    # extract filters
    setup_filters = _get_filters()
    assert setup_filters, 'no filters found'

    # read relevant filetypes
    contents = []
    template_suffixes = {'.html', '.j2', '.tmpl'}
    for search_dir in search_dirs:
        if not search_dir.is_dir():
            continue
        for file_path in templates_dir.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in template_suffixes:
                contents.append(file_path.read_text(encoding='utf-8', errors='ignore'))

    unused_filters = []
    for filter_name in setup_filters:
        pattern = re.compile(rf'\|\s*{re.escape(filter_name)}\b')
        if not any(pattern.search(content) for content in contents):
            unused_filters.append(filter_name)

    assert not unused_filters, f'unused Jinja filters: {", ".join(unused_filters)}'
