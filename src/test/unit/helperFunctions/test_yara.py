import unittest

from helperFunctions.yara import (
    get_borders, get_longest_unique_matches, get_matched_strings_dict, match_is_longer, matches_overlap
)


class TestHelperFunctionsYara(unittest.TestCase):

    a = (0x0, '$a', 'abcd')
    aa = (0x10, '$a', 'abcd')
    b = (0x1, '$a', 'bcd')
    c = (0x20, '$a', 'abc')

    def test_get_longest_matches(self):
        self.assertEqual(get_longest_unique_matches([self.a]), [self.a], "one match not correct")
        self.assertEqual(get_longest_unique_matches([self.a, self.b]), [self.a], "two overlapping matches not correct")
        self.assertEqual(get_longest_unique_matches([self.a, self.c]), [self.c, self.a], "two non overlapping matches")

    def test_match_is_longer(self):
        self.assertTrue(match_is_longer(self.a, self.b), "a longer b not true")
        self.assertFalse(match_is_longer(self.b, self.a), "b longer a not false")

    def test_matches_overlap(self):
        self.assertTrue(matches_overlap(self.a, self.b), "a and b overlap not true")
        self.assertTrue(matches_overlap(self.b, self.a), "b and a overlap not true")
        self.assertFalse(matches_overlap(self.a, self.c), "a and c overlap not false")
        self.assertFalse(matches_overlap(self.c, self.a), "c and a overlap not false")

    def test_get_borders(self):
        self.assertEqual(get_borders(self.a), (0x0, 0x4), "borders not correct")

    def test_get_matched_strings_dict(self):
        self.assertEqual(get_matched_strings_dict([self.a]), {'abcd': [0x0]}, "simple case not correct")
        self.assertEqual(get_matched_strings_dict([self.a, self.aa]), {'abcd': [0x0, 0x10]}, "two occurences not correct")
        complex_match_dict = get_matched_strings_dict([self.a, self.c])
        self.assertIn('abcd', complex_match_dict.keys(), "first string not found")
        self.assertIn('abc', complex_match_dict.keys(), "second string not found")
