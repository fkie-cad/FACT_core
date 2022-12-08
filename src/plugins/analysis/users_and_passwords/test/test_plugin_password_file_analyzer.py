from pathlib import Path

import pytest

from objects.file import FileObject

from ..code.password_file_analyzer import AnalysisPlugin, crack_hash, parse_john_output

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(dict(plugin_class=AnalysisPlugin))
class TestAnalysisPluginPasswordFileAnalyzer:
    def test_process_object_shadow_file(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'passwd_test'))
        processed_object = analysis_plugin.process_object(test_file)
        results = processed_object.processed_analysis[analysis_plugin.NAME]

        assert len(results) == 15
        for item in [
            'vboxadd:unix',
            'mongodb:unix',
            'clamav:unix',
            'pulse:unix',
            'johndoe:unix',
            'max:htpasswd',
            'test:mosquitto',
            'admin:htpasswd',
            'root:unix',
            'user:unix',
            'user2:unix',
            'nosalt:unix',
        ]:
            assert item in results
            assert item in results['summary']
        self._assert_pw_match(results, 'max:htpasswd', 'dragon')  # MD5 apr1
        self._assert_pw_match(results, 'johndoe:unix', '123456')
        self._assert_pw_match(results, 'test:mosquitto', '123456')
        self._assert_pw_match(results, 'admin:htpasswd', 'admin')  # SHA-1
        self._assert_pw_match(results, 'root:unix', 'root')  # DES
        self._assert_pw_match(results, 'user:unix', '1234')  # Blowfish / bcrypt
        self._assert_pw_match(results, 'user2:unix', 'secret')  # MD5
        self._assert_pw_match(results, 'nosalt:unix', 'root')  # MD5 without salt

    def test_process_object_fp_file(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'passwd_FP_test'))
        processed_object = analysis_plugin.process_object(test_file)
        results = processed_object.processed_analysis[analysis_plugin.NAME]
        assert len(results) == 1
        assert 'summary' in results and results['summary'] == []

    def test_process_object_password_in_binary_file(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'passwd.bin'))
        processed_object = analysis_plugin.process_object(test_file)
        results = processed_object.processed_analysis[analysis_plugin.NAME]

        assert len(results) == 4
        for item in ['johndoe:unix', 'max:htpasswd']:
            assert item in results
            assert item in results['summary']
        self._assert_pw_match(results, 'johndoe:unix', '123456')
        self._assert_pw_match(results, 'max:htpasswd', 'dragon')

    @staticmethod
    def _assert_pw_match(results: dict, key: str, pw: str):
        user, type_ = key.split(':')
        assert 'type' in results[key]
        assert 'password-hash' in results[key]
        assert 'password' in results[key]
        assert results[key]['type'] == type_
        assert results[key]['password'] == pw
        assert results['tags'][f'{user}_{pw}']['value'] == f'Password: {user}:{pw}'


def test_crack_hash_failure():
    passwd_entry = [
        b'user',
        b'$6$Ph+uRn1vmQ+pA7Ka$fcn9/Ln3W6c6oT3o8bWoLPrmTUs+NowcKYa52WFVP5qU5jzadqwSq8F+Q4AAr2qOC+Sk5LlHmisri4Eqx7/uDg==',
    ]
    result_entry = {}
    assert crack_hash(b':'.join(passwd_entry[:2]), result_entry) is False
    assert 'ERROR' in result_entry


def test_crack_hash_success():
    passwd_entry = (
        'test:$dynamic_82$2c93b2efec757302a527be320b005a935567f370f268a13936fa42ef331cc703'
        '6ec75a65f8112ce511ff6088c92a6fe1384fbd0f70a9bc7ac41aa6103384aa8c$HEX$010203040506'
    )
    result_entry = {}
    assert crack_hash(passwd_entry.encode(), result_entry, '--format=dynamic_82') is True
    assert 'password' in result_entry
    assert result_entry['password'] == '123456'


JOHN_FAIL_OUTPUT = 'No password hashes loaded (see FAQ)\n\n=== Results: ===\n0 password hashes cracked, 0 left'

JOHN_SUCCESS_OUTPUT = (
    'Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])\n'
    "Press 'q' or Ctrl-C to abort, almost any other key for status\n"
    'dragon           (max)\n'
    '1g 0:00:00:00 DONE (2022-06-13 12:33) 16.66g/s 9600p/s 9600c/s 9600C/s password..darkness\n'
    'Use the "--show" option to display all of the cracked passwords reliably\n'
    'Session completed\n\n'
    '=== Results: ===\n'
    'max:dragon\n\n'
    '1 password hash cracked, 0 left\n'
)


@pytest.mark.parametrize(
    'john_output, expected_result',
    [
        ('', []),
        (JOHN_FAIL_OUTPUT, ['0 password hashes cracked, 0 left']),
        (JOHN_SUCCESS_OUTPUT, ['max:dragon', '1 password hash cracked, 0 left']),
    ],
)
def test_parse_output(john_output, expected_result):
    assert parse_john_output(john_output) == expected_result
