from __future__ import annotations

import string

from more_itertools import chunked

HIGHLIGHTING_CLASSES = [
    (set(string.ascii_letters.encode()), 'number'),
    (set(string.digits.encode()), 'built_in'),
    (set(range(128, 255)), 'keyword'),
    ({0, 255}, 'comment'),  # \x00 and \xff
]
PRINTABLE = set(string.printable.encode()) - set(b'\n\t\r\x0b\x0c')
CLOSING_SPAN = '</span>'


def preview_data_as_hex(data: bytes, chunk_size: int = 16, offset: int = 0):
    start_offset, relative_offset = 0, offset
    output = [
        f'{"rel. offset".center(12)} | {"abs. offset".center(12)} | {"hex content".center(48)} | string preview',
        f'{"-" * 12} | {"-" * 12} | {"-" * 48} | {"-" * 16}',
    ]
    for line in chunked(data, chunk_size):
        hex_content, str_preview = _get_hex_and_str_preview(line)
        if len(line) < chunk_size:  # fill hex column if it isn't full
            hex_content += ' ' * (chunk_size - len(line)) * 3
        output.append(
            f'{_format_offset(start_offset)} | {_format_offset(relative_offset)} | {hex_content} | {str_preview}'
        )
        start_offset += chunk_size
        relative_offset += chunk_size
    return '\n'.join(output)


def _get_hex_and_str_preview(line: list[int]) -> tuple[str, str]:
    hex_content, str_preview = '', ''
    last_highlighting_class = None
    for char in line:
        highlighting_class = _get_highlighting_class(char)
        if _span_should_close(last_highlighting_class, highlighting_class):
            hex_content += CLOSING_SPAN
            str_preview += CLOSING_SPAN
        if _span_should_open(last_highlighting_class, highlighting_class):
            span = f'{_get_html_span(highlighting_class)}'
            hex_content += span
            str_preview += span
        hex_content += f' {_chr_to_hex(char)}'
        str_preview += f'{chr(char)}' if char in PRINTABLE else '.'
        last_highlighting_class = highlighting_class
    if last_highlighting_class is not None:  # close last span
        hex_content += CLOSING_SPAN
        str_preview += CLOSING_SPAN
    return hex_content, str_preview


def _span_should_close(last_class: str | None, current_class: str | None) -> bool:
    return last_class is not None and current_class != last_class


def _span_should_open(last_class: str | None, current_class: str | None) -> bool:
    return current_class is not None and current_class != last_class


def _get_highlighting_class(char: int) -> str | None:
    for char_range, highlighting_class in HIGHLIGHTING_CLASSES:
        if char in char_range:
            return highlighting_class
    return None


def _get_html_span(highlighting_class: str) -> str:
    return f'<span class="hljs-{highlighting_class}">'  # reuse highlight.js classes for highlighting


def _chr_to_hex(char: int) -> str:
    return f'{char:#04x}'[2:].upper()


def _format_offset(offset: int) -> str:
    return f'{offset:#08x}'.rjust(12)
