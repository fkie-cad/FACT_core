# ruff: noqa: S112
import ast
import re
from pathlib import Path


def test_unused_finja_filter() -> None:
    filters_file_path = Path('src/web_interface/components/jinja_filter.py')
    templates_dir = Path('src/')

    assert filters_file_path.exists(), f'{filters_file_path} not found'
    assert templates_dir.is_dir(), f'Verzeichnis {templates_dir} not found'

    # extract filters
    tree = ast.parse(filters_file_path.read_text(encoding='utf-8'))
    setup_filters = next(
        (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == '_setup_filters'), None
    )
    assert setup_filters, '_setup_filters not found'

    filter_names = set()
    for node in ast.walk(setup_filters):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'update'
            and node.args
            and isinstance(node.args[0], ast.Dict)
        ):
            for key in node.args[0].keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    filter_names.add(key.value)

    assert filter_names, 'no filters found in _setup_filters'

    # read relevant filetypes
    contents = []
    template_suffixes = {'.html', '.j2', '.tmpl'}
    for file_path in templates_dir.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() in template_suffixes:
            try:
                contents.append(file_path.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                continue

    unused_filters = []
    for filter_name in filter_names:
        pattern = re.compile(rf'\|\s*{re.escape(filter_name)}\b')
        if not any(pattern.search(content) for content in contents):
            unused_filters.append(filter_name)

    assert not unused_filters, f'unused Jinja-Filter: {", ".join(unused_filters)}'
