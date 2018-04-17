import unittest
from web_interface.components.additional_functions.hex_dump import _structure_hex_dump, _process_hex_bytes, _process_one_column, convert_binary_to_ascii_with_dots, create_hex_dump


class TestHexDump(unittest.TestCase):
    def test_process_hex_bytes(self):
        input_data = '00112233445566778899'
        expected_output = '00 11 22 33  44 55 66 77  88 99 '
        self.assertEqual(_process_hex_bytes(input_data), expected_output, 'hex byte processing not correct')

    def test_structure_hex_dump(self):
        input_data = '00 11 22 33 44 55 66 77 88 99'
        expected_output = '00 11 22 33  44 55 66 77  88 99'
        self.assertEqual(_structure_hex_dump(input_data), expected_output, 'structuring not correct')

    def test_process_ascii_bytes(self):
        input_bytes = b'GoodCharacters\xBA\xDCharacters'
        expected_output = 'GoodCharacters..haracters'

        self.assertEqual(len(convert_binary_to_ascii_with_dots(input_bytes)), len(input_bytes), 'length of strings do not match')
        self.assertEqual(convert_binary_to_ascii_with_dots(input_bytes), expected_output, 'ascii byte processing not correct')

    def test_process_one_column(self):
        input_bytes = b'Bytes.Lotso\xFBytes'
        expected_hex, expected_ascii = '42 79 74 65  73 2e 4c 6f  74 73 6f fb  79 74 65 73  ', 'Bytes.Lotso.ytes'
        resulting_ascii, resulting_hex, offset = _process_one_column(input_bytes, 0)
        self.assertEqual(resulting_ascii, expected_ascii, 'ascii didn\'t match')
        self.assertEqual(resulting_hex, expected_hex, 'hex didn\'t match')
        self.assertEqual(offset, 0, 'non zero offset')

    def test_create_hex_dump(self):
        not_enough_bytes = b'NotEnough'
        bad_result = create_hex_dump(not_enough_bytes)
        assert 'binary is too small for preview' == bad_result, 'binary should not be big enough'

        enough_bytes = b'\xFF' * 64 + b'\x00' * 64
        good_result = create_hex_dump(enough_bytes)
        assert 'ff ff' in good_result, 'hex dump was not created correctly'
