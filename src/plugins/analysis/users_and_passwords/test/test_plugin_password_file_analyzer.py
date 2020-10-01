from pathlib import Path

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.password_file_analyzer import AnalysisPlugin

TEST_DATA_DIR = Path(__file__).parent / 'data'


class TestAnalysisPluginPasswordFileAnalyzer(AnalysisPluginTest):

    PLUGIN_NAME = 'users_and_passwords'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object_shadow_file(self):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'passwd_test'))
        processed_object = self.analysis_plugin.process_object(test_file)
        results = processed_object.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 8)
        for item in ['vboxadd', 'mongodb', 'clamav', 'pulse', 'johndoe', 'max']:
            self.assertIn(item, results)
            self.assertIn(item, results['summary'])
        self.assertIn('password-hash', results['max']['passwd'])
        self.assertIn('password', results['max']['passwd'])
        self.assertEqual(results['max']['passwd']['password'], 'dragon')
        self.assertIn('password-hash', results['johndoe']['passwd'])
        self.assertIn('password', results['johndoe']['passwd'])
        self.assertEqual(results['johndoe']['passwd']['password'], '123456')
        self.assertEqual(results['tags']['johndoe_123456']['value'], 'Password: johndoe:123456')

    def test_process_object_password_in_binary_file(self):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'passwd.bin'))
        processed_object = self.analysis_plugin.process_object(test_file)
        results = processed_object.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 4)
        for item in ['johndoe', 'max']:
            self.assertIn(item, results)
            self.assertIn(item, results['summary'])
        self.assertIn('password-hash', results['johndoe']['passwd'])
        self.assertIn('password', results['johndoe']['passwd'])
        self.assertEqual(results['johndoe']['passwd']['password'], '123456')
        self.assertIn('password-hash', results['max']['passwd'])
        self.assertIn('password', results['max']['passwd'])
        self.assertEqual(results['max']['passwd']['password'], 'dragon')

    def test_crack_hash_failure(self):
        passwd_entry = [b'user', b'$6$Ph+uRn1vmQ+pA7Ka$fcn9/Ln3W6c6oT3o8bWoLPrmTUs+NowcKYa52WFVP5qU5jzadqwSq8F+Q4AAr2qOC+Sk5LlHmisri4Eqx7/uDg==']
        result_entry = {}
        assert self.analysis_plugin._crack_hash(passwd_entry, result_entry) is False  # pylint: disable=protected-access
        assert 'ERROR' in result_entry


def test_crack_mosquitto_hash():
    passwd_entry = 'apson:$dynamic_82$7dc9fdfcb9f75ba73aa13de8f1b5a82cfae64d4b3e368c1c2986b9d961553f9a94e63cda76ac12abc17e438000af6a8e0be4a4e4b9479a2b2b8b812ac7bfee0e$HEX$3e1fae467d6f990fa903b29a'
    result_entry = {}
    assert AnalysisPlugin._crack_mosquitto_hash(passwd_entry, result_entry) is True  # pylint: disable=protected-access
    assert 'password' in result_entry
