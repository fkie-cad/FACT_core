from pathlib import Path

import pytest

from ..code.password_file_analyzer import AnalysisPlugin
from ..internal.crack_password import _parse_john_output, crack_hash

TEST_DATA_DIR = Path(__file__).parent / 'data'
PW_TYPES = ['unix', 'mosquitto', 'http']


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginPasswordFileAnalyzer:
    def test_process_object_shadow_file(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'passwd_test'
        with test_file.open() as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        summary = analysis_plugin.summarize(result)

        matches = {(i.username, i.type, i.password) for type_ in PW_TYPES for i in getattr(result, type_)}
        for pw_tuple in [
            ('vboxadd', 'unix', None),
            ('mongodb', 'unix', None),
            ('clamav', 'unix', None),
            ('pulse', 'unix', None),
            ('johndoe', 'unix', '123456'),
            ('max', 'http', 'dragon'),  # MD5 apr1
            ('test', 'mosquitto', '123456'),
            ('admin', 'http', 'admin'),  # SHA-1
            ('root', 'unix', 'root'),  # DES
            ('user', 'unix', '1234'),  # Blowfish / bcrypt
            ('user2', 'unix', 'secret'),  # MD5
            ('nosalt', 'unix', 'root'),  # MD5 without salt
        ]:
            assert pw_tuple in matches
            user, type_, _ = pw_tuple
            assert f'{user}:{type_}' in summary

    def test_process_object_fp_file(self, analysis_plugin):
        with (TEST_DATA_DIR / 'passwd_FP_test').open() as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        summary = analysis_plugin.summarize(result)

        assert len(result.unix) == 0
        assert len(result.http) == 0
        assert len(result.mosquitto) == 0
        assert summary == []

    def test_process_object_password_in_binary_file(self, analysis_plugin):
        with (TEST_DATA_DIR / 'passwd.bin').open() as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        summary = analysis_plugin.summarize(result)

        assert len(result.unix) == 1
        assert len(result.http) == 1
        for item in ['johndoe:unix', 'max:http']:
            assert item in summary
        for user, type_, pw in [
            ('johndoe', 'unix', '123456'),
            ('max', 'http', 'dragon'),
        ]:
            assert any(i.username == user and i.type == type_ and i.password == pw for i in getattr(result, type_))


def test_crack_hash_failure():
    passwd_entry = [b'user', b'BfKEUi/mdF1D2']
    pw, error = crack_hash(b':'.join(passwd_entry[:2]))
    assert pw is None
    assert error == 'password cracking not successful'


def test_hash_unsupported():
    passwd_entry = [b'user', b'foobar']
    pw, error = crack_hash(b':'.join(passwd_entry[:2]))
    assert pw is None
    assert error == 'hash type is not supported'


def test_crack_hash_success():
    passwd_entry = (
        'test:$dynamic_82$2c93b2efec757302a527be320b005a935567f370f268a13936fa42ef331cc703'
        '6ec75a65f8112ce511ff6088c92a6fe1384fbd0f70a9bc7ac41aa6103384aa8c$HEX$010203040506'
    )
    pw, error = crack_hash(passwd_entry.encode(), '--format=dynamic_82')
    assert error is None
    assert pw == '123456'


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
    ('john_output', 'expected_result'),
    [
        ('', []),
        (JOHN_FAIL_OUTPUT, ['0 password hashes cracked, 0 left']),
        (JOHN_SUCCESS_OUTPUT, ['max:dragon', '1 password hash cracked, 0 left']),
    ],
)
def test_parse_output(john_output, expected_result):
    assert _parse_john_output(john_output) == expected_result
