import binascii

from flask import Markup

from compare.PluginBase import CompareBasePlugin

ASCII_RANGE = (32, 127)
BYTES_TO_SHOW = 512
COLUMN_WIDTH = 32


class Mask:
    GREEN = '5bc85b'
    BLUE = '7070f1'
    RED = 'fb5151'


class ComparePlugin(CompareBasePlugin):
    '''
    Shows a "binwalk -Ww"-ish comparison of the FOs headers in highlighted hexadecimal
    '''
    NAME = 'File_Header'
    DEPENDENCIES = []
    FILE = __file__

    def compare_function(self, fo_list):
        binaries = [fo.binary for fo in fo_list]
        lower_bound = min(min(len(binary) for binary in binaries), BYTES_TO_SHOW)

        offsets = self._get_offsets(lower_bound)
        hexdiff = self._get_highlighted_hex_string(binaries, lower_bound)
        ascii_representation = self._get_ascii_representation(binaries, lower_bound)

        return dict(hexdiff=hexdiff, offsets=offsets, ascii=ascii_representation)

    def _get_ascii_representation(self, binaries, lower_bound):
        part = binaries[0][0:lower_bound]
        bytes_in_ascii = replace_none_ascii_with_dots(part).decode()
        if not len(bytes_in_ascii) == lower_bound:
            raise RuntimeError('Converting binary to ascii failed')

        number_of_rows = self._get_number_of_rows(lower_bound)
        ascii_string = '<p style="font-family: monospace; color: #eee;"><br />'
        for index in range(number_of_rows):
            partial = bytes_in_ascii[index * COLUMN_WIDTH:(index + 1) * COLUMN_WIDTH]
            ascii_string += f'| {self._replace_forbidden_html_characters(partial)} |<br />'

        return Markup(ascii_string + '</p>')

    def _get_highlighted_hex_string(self, binaries, lower_bound):
        mask = self._get_byte_mask(binaries, lower_bound)
        if not len(mask) == lower_bound:
            raise RuntimeError('Failure in processing bytes for hex mask')

        first_binary_in_hex = self._get_first_512_bytes_in_hex(binaries[0])
        if not len(first_binary_in_hex) >= len(mask) * 2:
            raise RuntimeError('First binary is too small for depiction')

        highlighted_string = '<p style="font-family: monospace;">'

        for index, color in enumerate(mask):
            if index % COLUMN_WIDTH == 0:
                highlighted_string += '<br />'

            to_highlight = first_binary_in_hex[2 * index:2 * index + 2]
            highlighted_string += f'<span style="color: #{color}">{to_highlight}</span>&nbsp;'

        return Markup(highlighted_string + '</p>')

    def _get_offsets(self, lower_bound):
        number_of_rows = self._get_number_of_rows(lower_bound)

        offsets_string = '<p style="font-family: monospace; color: #eee;"><br />'
        for row in range(number_of_rows):
            offsets_string += f'0x{row * COLUMN_WIDTH:03X}<br />'

        return Markup(offsets_string + '</p>')

    def _get_byte_mask(self, binaries, lower_bound):
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
    def _get_first_512_bytes_in_hex(binary):
        first_bytes = binary[0:BYTES_TO_SHOW]
        hex_bytes = binascii.b2a_hex(first_bytes).decode()
        return hex_bytes.upper()

    @staticmethod
    def _replace_forbidden_html_characters(dangerous_string):
        translation = {'&': '&amp;', '<': '&lt;', '>': '&gt;'}
        return dangerous_string.translate(str.maketrans(translation))

    @staticmethod
    def _at_least_two_are_common(values):
        while values:
            value = values.pop()
            if value in values:
                return True
        return False

    @staticmethod
    def _get_number_of_rows(lower_bound):
        return lower_bound // COLUMN_WIDTH if lower_bound % COLUMN_WIDTH == 0 else lower_bound // COLUMN_WIDTH + 1


def replace_none_ascii_with_dots(binary_block):
    ascii_range = set(range(*ASCII_RANGE))
    return b''.join(
        (binary_block[index:index + 1] if char in ascii_range else b'.' for index, char in enumerate(binary_block)),
    )
