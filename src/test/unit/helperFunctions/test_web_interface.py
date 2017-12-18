import unittest

from helperFunctions.web_interface import filter_out_illegal_characters


class TestHelperFunctionsWebInterface(unittest.TestCase):

    def test_filter_out_illegal_characters(self):
        self.assertEqual(filter_out_illegal_characters(''), '')
        self.assertEqual(filter_out_illegal_characters('abc'), 'abc')
        self.assertEqual(filter_out_illegal_characters('Größer 2'), 'Größer 2')
        self.assertEqual(filter_out_illegal_characters('{"$test": ["test"]}'), 'test test')
        self.assertEqual(filter_out_illegal_characters(None), None)
