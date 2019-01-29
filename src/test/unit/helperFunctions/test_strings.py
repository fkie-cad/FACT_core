import unittest

from helperFunctions.strings import find_all_utf16_patterns, decode_strings, find_all_strings


class TestHelperFunctionsStrings(unittest.TestCase):

    def setUp(self):
        self.strings = ['first string', 'second<>_$tring!', 'third:?-+012345/\\string']

    def test_find_utf16_strings(self):
        test_input = b'\xaa\xbb'.join([s.encode('utf-16') for s in self.strings])
        result = find_all_utf16_patterns(test_input, 6)
        for s in decode_strings(result, 'utf-16'):
            self.assertIn(s, self.strings)

    def test_find_all_strings(self):
        input_data = b'\x03\x01[test_string1!\\]\x03\x01(t3st 5tring2?)\x03to\x01[test_string1!\\]'
        result = find_all_strings(input_data)
        self.assertEqual(result, ['(t3st 5tring2?)', '[test_string1!\\]'], "result not correct")
