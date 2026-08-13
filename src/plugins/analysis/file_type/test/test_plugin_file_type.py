from __future__ import annotations

import io
import time
from pathlib import Path

import pytest

from helperFunctions import magic
from test.common_helper import get_test_data_dir

from ..code.file_type import AnalysisPlugin


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_detect_type_of_file(analysis_plugin):
    result = analysis_plugin.analyze(
        io.FileIO(f'{get_test_data_dir()}/container/test.zip'),
        {},
        {},
    )
    summary = analysis_plugin.summarize(result)

    assert result.mime == 'application/zip', 'mime-type not detected correctly'
    assert result.full.startswith('Zip archive data,'), 'full type not correct'

    assert summary == ['application/zip']


def print_table(rows: list[list[str]]) -> None:
    headers = ['file', 'tool', 'type/label', 'MIME', 'description', 'summary', 'confidence', 'runtime (s)']
    widths = [max(len(header), *(len(row[i]) for row in rows)) for i, header in enumerate(headers)]

    def format_row(row: list[str]) -> str:
        return ' | '.join(value.ljust(widths[i]) for i, value in enumerate(row))

    print('\n' + format_row(headers))  # noqa: T201
    print('-+-'.join('-' * width for width in widths))  # noqa: T201
    for row in rows:
        print(format_row(row))  # noqa: T201


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_compare_magic_and_magika(analysis_plugin):
    container_dir = Path(get_test_data_dir()) / 'container'
    assert container_dir.is_dir(), f'404 no: {container_dir}'

    file_paths = sorted((path for path in container_dir.rglob('*') if path.is_file()), key=str)
    assert file_paths, f'No data found {container_dir}.'

    rows: list[list[str]] = []

    for file_path in file_paths:
        relative_path = str(file_path.relative_to(container_dir))

        magic_start = time.perf_counter()
        magic_mime, magic_full = magic.from_file(str(file_path), mime=True), magic.from_file(str(file_path), mime=False)
        magic_runtime = time.perf_counter() - magic_start

        magika_start = time.perf_counter()
        with io.FileIO(str(file_path)) as input_file:
            result = analysis_plugin.analyze(
                input_file,
                {},
                {},
            )
        summary = analysis_plugin.summarize(result)
        magika_runtime = time.perf_counter() - magika_start

        magika = result.magika
        rows.extend(
            [
                [relative_path, 'magic', '', magic_mime or '', magic_full or '', '', '', f'{magic_runtime:.4f}'],
                [
                    relative_path,
                    'magika',
                    magika.label if magika is not None else '',
                    magika.mime if magika is not None else result.mime or '',
                    magika.description if magika is not None else result.full or '',
                    ', '.join(map(str, summary)),
                    f'{magika.confidence:.2f}' if magika is not None and magika.confidence is not None else '',
                    f'{magika_runtime:.4f}',
                ],
            ]
        )

    print_table(rows)
