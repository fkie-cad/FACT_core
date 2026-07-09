from __future__ import annotations

import binascii
from typing import TYPE_CHECKING

from markupsafe import Markup

from compare.PluginBase import CompareBasePlugin

if TYPE_CHECKING:
    from objects.file import FileObject

ASCII_RANGE = (32, 127)
BYTES_TO_SHOW = 512
COLUMN_WIDTH = 32


class Mask:
    GREEN = '5bc85b'
    BLUE = '7070f1'
    RED = 'fb5151'


class ComparePlugin(CompareBasePlugin):
    """
    Shows a "binwalk -Ww"-ish comparison of the FOs headers in highlighted hexadecimal
    """

    NAME = 'File_Header'
    DEPENDENCIES = []  # noqa: RUF012
    FILE = __file__

    def compare_function(self, fo_list: list[FileObject], dependency_results: dict[str, dict]) -> dict:
        del dependency_results
        binaries = [fo.binary for fo in fo_list]
        lower_bound = min(*(len(binary) for binary in binaries), BYTES_TO_SHOW)

        offsets = self._get_offsets(lower_bound)
        hexdiff = self._get_highlighted_hex_string(binaries, lower_bound)
        ascii_representation = self._get_ascii_representation(binaries, lower_bound)

        return {'hexdiff': hexdiff, 'offsets': offsets, 'ascii': ascii_representation}

    def _get_ascii_representation(self, binaries: list[bytes], lower_bound: int) -> Markup:
        part = binaries[0][0:lower_bound]
        bytes_in_ascii = replace_none_ascii_with_dots(part).decode()
        if not len(bytes_in_ascii) == lower_bound:
            raise RuntimeError('Converting binary to ascii failed')

        number_of_rows = self._get_number_of_rows(lower_bound)
        body = Markup('<br />')
        for index in range(number_of_rows):
            partial = bytes_in_ascii[index * COLUMN_WIDTH : (index + 1) * COLUMN_WIDTH]
            body += Markup('| {} |<br />').format(partial)

        return Markup('<p style="font-family: monospace; color: #eee;">{}</p>').format(body)

    def _get_highlighted_hex_string(self, binaries: list[bytes], lower_bound: int) -> Markup:
        mask = self._get_byte_mask(binaries, lower_bound)
        if not len(mask) == lower_bound:
            raise RuntimeError('Failure in processing bytes for hex mask')

        first_binary_in_hex = self._get_first_512_bytes_in_hex(binaries[0])
        if not len(first_binary_in_hex) >= len(mask) * 2:
            raise RuntimeError('First binary is too small for depiction')

        body = Markup('')
        for index, color in enumerate(mask):
            if index % COLUMN_WIDTH == 0:
                body += Markup('<br />')
            to_highlight = first_binary_in_hex[2 * index : 2 * index + 2]
            body += Markup('<span style="color: #{}">{}</span>&nbsp;').format(color, to_highlight)

        return Markup('<p style="font-family: monospace;">{}</p>').format(body)

    def _get_offsets(self, lower_bound: int) -> Markup:
        number_of_rows = self._get_number_of_rows(lower_bound)
        rows = Markup('<br />').join(Markup('0x{:03X}').format(row * COLUMN_WIDTH) for row in range(number_of_rows))
        return Markup('<p style="font-family: monospace; color: #eee;"><br />{}</p>').format(rows)

    def _get_byte_mask(self, binaries: list[bytes], lower_bound: int) -> list[str]:
        mask = []

        for index in range(lower_bound):
            reference = binaries[0][index]
            if all(binary[index] == reference for binary in binaries[1:]):
                mask.append(Mask.GREEN)
            elif self._at_least_two_are_common([binary[index] for binary in binaries]):
                mask.append(Mask.BLUE)
            else:
                mask.append(Mask.RED)

        return mask

    @staticmethod
    def _get_first_512_bytes_in_hex(binary: bytes) -> str:
        first_bytes = binary[0:BYTES_TO_SHOW]
        hex_bytes = binascii.b2a_hex(first_bytes).decode()
        return hex_bytes.upper()

    @staticmethod
    def _at_least_two_are_common(values: list[int]) -> bool:
        return len(set(values)) < len(values)

    @staticmethod
    def _get_number_of_rows(lower_bound: int) -> int:
        return lower_bound // COLUMN_WIDTH if lower_bound % COLUMN_WIDTH == 0 else lower_bound // COLUMN_WIDTH + 1


def replace_none_ascii_with_dots(binary_block: bytes) -> bytes:
    ascii_range = set(range(*ASCII_RANGE))
    return b''.join(
        (binary_block[index : index + 1] if char in ascii_range else b'.' for index, char in enumerate(binary_block))
    )
