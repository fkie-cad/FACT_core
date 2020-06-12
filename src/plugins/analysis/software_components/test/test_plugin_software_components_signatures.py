import os

from common_helper_files import get_dir_of_file

from test.yara_signature_testing import SignatureTestingMatching, SignatureTestingMeta

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')
SIGNATURE_PATH = os.path.join(get_dir_of_file(__file__), '../signatures/')
TEST_SIGNATURE_PATH = os.path.join(get_dir_of_file(__file__), '../test/data/signatures/')


class TestSoftwareSignatureMeta:

    @classmethod
    def setup_class(cls):
        cls.sigTest = SignatureTestingMeta()

    def test_check_meta_fields(self):
        missing_fields = self.sigTest.check_meta_fields(SIGNATURE_PATH)
        assert not missing_fields, 'Missing meta fields: {}'.format(missing_fields.__str__())

    def test_check_meta_fields_missing(self):
        missing_fields = self.sigTest.check_meta_fields(TEST_SIGNATURE_PATH)
        assert len(missing_fields) == 3
        assert all(
            entry in missing_fields
            for entry in ['website in missing_meta_1', 'description in missing_meta_1', 'ALL in missing_meta_2']
        )


class TestAllKnownSoftwareMatched:

    def setup_method(self):
        self.sig_tester = SignatureTestingMatching()  # pylint: disable=attribute-defined-outside-init

    def test_all_signatures_matched(self):
        diff = self.sig_tester.check(SIGNATURE_PATH, os.path.join(TEST_DATA_DIR, 'software_component_test_list.txt'))
        assert diff == set(), 'Missing signature for {}'.format(diff)
