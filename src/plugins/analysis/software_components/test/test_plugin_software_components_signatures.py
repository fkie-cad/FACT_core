import unittest
from common_helper_files import get_dir_of_file
import os

from helperFunctions.yara_signature_testing import SignatureTestingMatching, SignatureTestingMeta

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')
SIGNATURE_PATH = os.path.join(get_dir_of_file(__file__), '../signatures/')


class TestSoftwareSignatureMeta(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sigTest = SignatureTestingMeta()

    def test_check_meta_fields(self):
        missing_fields = self.sigTest.check_meta_fields(SIGNATURE_PATH)
        self.assertEqual(len(missing_fields), 0, 'Missing meta fields: {}'.format(missing_fields.__str__()))


class TestAllKnownSoftwareMatched(unittest.TestCase):

    def setUp(self):
        self.sig_tester = SignatureTestingMatching()

    def test_all_signatures_matched(self):
        diff = self.sig_tester.check(SIGNATURE_PATH, os.path.join(TEST_DATA_DIR, 'software_component_test_list.txt'))
        self.assertEqual(diff, set(), 'Missing signature for {}'.format(diff))
