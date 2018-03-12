import binascii

from flask import Markup

from compare.PluginBase import CompareBasePlugin
from storage.binary_service import BinaryService
from web_interface.components.additional_functions.hex_dump import convert_binary_to_ascii_with_dots

COLUMN_WIDTH = 32
BYTES_TO_SHOW = 512


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

    def __init__(self, plugin_administrator, config=None, db_interface=None, plugin_path=__file__):
        super().__init__(plugin_administrator, config=config, db_interface=db_interface, plugin_path=plugin_path)

    def compare_function(self, fo_list):
        self._add_binaries_to_fos(fo_list)
        binaries = [fo.binary for fo in fo_list]
        lower_bound = min(min(len(binary) for binary in binaries), BYTES_TO_SHOW)

        offsets = self._get_offsets(lower_bound)
        hexdiff = self._get_hightlighted_hex_string(binaries, lower_bound)
        ascii_representation = self._get_ascii_representation(binaries, lower_bound)

        return dict(hexdiff=hexdiff, offsets=offsets, ascii=ascii_representation)

    def _get_ascii_representation(self, binaries, lower_bound):
        part = binaries[0][0:lower_bound]
        bytes_in_ascii = convert_binary_to_ascii_with_dots(part)
        assert len(bytes_in_ascii) == lower_bound

        number_of_rows = self._get_number_of_rows(lower_bound)
        ascii_string = '<p style="font-family: monospace; color: #eee;"><br />'
        for index in range(number_of_rows):
            partial = bytes_in_ascii[index * COLUMN_WIDTH:(index + 1) * COLUMN_WIDTH]
            ascii_string += '| {} |<br />'.format(self._replace_forbidden_html_characters(partial))

        return Markup(ascii_string + '</p>')

    def _get_hightlighted_hex_string(self, binaries, lower_bound):
        mask = self._get_byte_mask(binaries, lower_bound)
        first_binary_in_hex = self._get_first_512_bytes_in_hex(binaries[0])
        assert len(first_binary_in_hex) >= len(mask) * 2

        highlighted_string = '<p style="font-family: monospace;">'

        for index, color in enumerate(mask):
            if index % COLUMN_WIDTH == 0:
                highlighted_string += '<br />'

            to_highlight = first_binary_in_hex[2 * index:2 * index + 2]
            highlighted_string += '<span style="color: #{}">{}</span>&nbsp;'.format(color, to_highlight)

        return Markup(highlighted_string + '</p>')

    def _get_offsets(self, lower_bound):
        number_of_rows = self._get_number_of_rows(lower_bound)

        offsets_string = '<p style="font-family: monospace; color: #eee;"><br />'
        for row in range(number_of_rows):
            offsets_string += '0x{:03X}<br />'.format(row * COLUMN_WIDTH)

        return Markup(offsets_string + '</p>')

    def _get_byte_mask(self, binaries, lower_bound):
        mask = list()

        for index in range(lower_bound):
            reference = binaries[0][index]
            if all(binary[index] == reference for binary in binaries[1:]):
                mask.append(Mask.GREEN)
            elif self._at_least_two_are_common([binary[index] for binary in binaries]):
                mask.append(Mask.BLUE)
            else:
                mask.append(Mask.RED)

        assert len(mask) == lower_bound, 'failure in processing'
        return mask

    @staticmethod
    def _get_first_512_bytes_in_hex(binary):
        first_bytes = binary[0:BYTES_TO_SHOW]
        hex_bytes = binascii.b2a_hex(first_bytes).decode()
        return hex_bytes.upper()

    def _add_binaries_to_fos(self, fo_list):
        bs = BinaryService(config=self.config)
        for fo in fo_list:
            fo.binary = bs.get_binary_and_file_name(fo.uid)[0]

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
