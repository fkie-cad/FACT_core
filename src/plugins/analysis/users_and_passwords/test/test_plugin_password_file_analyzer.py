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

        self.assertEqual(len(results), 10)
        for item in ['vboxadd:unix', 'mongodb:unix', 'clamav:unix', 'pulse:unix', 'johndoe:unix', 'max:unix', 'test:mosquitto']:
            self.assertIn(item, results)
            self.assertIn(item, results['summary'])
        self.assertIn('type', results['max:unix'])
        self.assertIn('password-hash', results['max:unix'])
        self.assertIn('password', results['max:unix'])
        self.assertEqual(results['max:unix']['type'], 'unix')
        self.assertEqual(results['max:unix']['password'], 'dragon')
        self.assertIn('type', results['johndoe:unix'])
        self.assertIn('password-hash', results['johndoe:unix'])
        self.assertIn('password', results['johndoe:unix'])
        self.assertEqual(results['johndoe:unix']['type'], 'unix')
        self.assertEqual(results['johndoe:unix']['password'], '123456')
        self.assertEqual(results['tags']['johndoe_123456']['value'], 'Password: johndoe:123456')
        self.assertIn('type', results['test:mosquitto'])
        self.assertIn('password-hash', results['test:mosquitto'])
        self.assertIn('password', results['test:mosquitto'])
        self.assertEqual(results['test:mosquitto']['type'], 'mosquitto')
        self.assertEqual(results['test:mosquitto']['password'], '123456')
        self.assertEqual(results['tags']['test_123456']['value'], 'Password: test:123456')

    def test_process_object_password_in_binary_file(self):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'passwd.bin'))
        processed_object = self.analysis_plugin.process_object(test_file)
        results = processed_object.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(len(results), 4)
        for item in ['johndoe:unix', 'max:unix']:
            self.assertIn(item, results)
            self.assertIn(item, results['summary'])
        self.assertIn('password-hash', results['johndoe:unix'])
        self.assertIn('password', results['johndoe:unix'])
        self.assertEqual(results['johndoe:unix']['password'], '123456')
        self.assertIn('password-hash', results['max:unix'])
        self.assertIn('password', results['max:unix'])
        self.assertEqual(results['max:unix']['password'], 'dragon')

    def test_crack_hash_failure(self):
        passwd_entry = [b'user', b'$6$Ph+uRn1vmQ+pA7Ka$fcn9/Ln3W6c6oT3o8bWoLPrmTUs+NowcKYa52WFVP5qU5jzadqwSq8F+Q4AAr2qOC+Sk5LlHmisri4Eqx7/uDg==']
        result_entry = {}
        assert self.analysis_plugin._crack_hash(b':'.join(passwd_entry[:2]), result_entry) is False  # pylint: disable=protected-access
        assert 'ERROR' in result_entry

    def test_crack_hash_success(self):
        passwd_entry = 'test:$dynamic_82$2c93b2efec757302a527be320b005a935567f370f268a13936fa42ef331cc7036ec75a65f8112ce511ff6088c92a6fe1384fbd0f70a9bc7ac41aa6103384aa8c$HEX$010203040506'
        result_entry = {}
        assert self.analysis_plugin._crack_hash(passwd_entry.encode(), result_entry, '--format=dynamic_82') is True  # pylint: disable=protected-access
        assert 'password' in result_entry
        assert result_entry['password'] == '123456'
