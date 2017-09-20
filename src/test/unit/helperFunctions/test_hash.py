'''
Created on 21.08.2015

@author: weidenba
'''
import unittest

from helperFunctions.hash import get_sha256, get_md5, get_ssdeep, get_ssdeep_comparison, check_similarity_of_sets


class Test_hash_generation(unittest.TestCase):
    test_string = "test string"
    test_string_SHA256 = "d5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b"
    test_string_MD5 = "6f8db599de986fab7a21625b7916589c"
    test_string_SSDEEP = "3:Hv2:HO"

    def test_get_sha256(self):
        self.assertEqual(get_sha256(self.test_string), self.test_string_SHA256, "not correct from string")

    def test_get_md5(self):
        self.assertEqual(get_md5(self.test_string), self.test_string_MD5, "not correct from string")

    def test_get_ssdeep(self):
        self.assertEqual(get_ssdeep(self.test_string), self.test_string_SSDEEP, "not correct from string")

    def test_get_ssdeep_comparison(self):
        factor = get_ssdeep_comparison('192:3xaGk2v7RNOrG4D9tVwTiGTUwMyKP3JDddt2vT3GiH3gnK:BHTWy66gnK', '192:3xaGk2v7RNOrG4D9tVwTiGTUwMyKP3JDddt2vT3GK:B')
        self.assertEqual(96, factor, 'ssdeep similarity seems to be out of shape')

    def test_check_similarity_of_sets(self):
        pairs = [{0, 1}, {2, 3}, {4, 8}, {1, 8}, {3, 4}, {0, 8}]
        pair_one = [{0, 8}, {1, 8}]
        pair_two = [{2, 3}, {3, 4}]
        self.assertTrue(check_similarity_of_sets(pair_one, pairs), 'set simililarity does not work correctly')
        self.assertFalse(check_similarity_of_sets(pair_two, pairs), 'set simililarity does not work correctly')
