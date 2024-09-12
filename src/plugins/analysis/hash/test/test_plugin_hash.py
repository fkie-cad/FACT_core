import os
from pathlib import Path

import pytest

from ..code.hash import AnalysisPlugin, get_imphash, get_ssdeep, get_tlsh

TEST_DATA_DIR = Path(__file__).parent / 'data'
TEST_FILE = TEST_DATA_DIR / 'ls'
MD5_LEN = 32
TEST_STRING = b'test string'


class MockTypeResultSchema:
    mime = 'application/x-executable'


ANALYSIS_RESULT = {'file_type': MockTypeResultSchema()}


@pytest.mark.backend_config_overwrite(
    {
        'plugin': {
            'file_hashes': {
                'name': 'file_hashes',
                'hashes': ['md5', 'sha1', 'foo'],
            },
        }
    },
)
@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginHash:
    def test_all_hashes(self, analysis_plugin):
        with TEST_FILE.open('rb') as fp:
            result = analysis_plugin.analyze(fp, {}, ANALYSIS_RESULT)

        assert result.md5 is not None
        assert result.sha1 is not None
        assert result.ssdeep is not None
        assert result.imphash is not None
        assert result.md5 == '87b02c9bea4be534649d3ab0b6f040a0', 'hash not correct'

    def test_imphash(self, analysis_plugin):
        with TEST_FILE.open('rb') as fp:
            result = analysis_plugin.analyze(fp, {}, ANALYSIS_RESULT)

        assert isinstance(result.imphash, str), 'imphash should be a string'
        assert len(result.imphash) == MD5_LEN, 'imphash does not look like an md5'
        assert result.imphash == 'd9eccd5f72564ac07601458b26040259'


def test_get_ssdeep():
    assert get_ssdeep(TEST_STRING) == '3:Hv2:HO', 'not correct from string'


def test_imphash_bad_file():
    this_file = Path(__file__)
    with this_file.open('rb') as fp:
        assert get_imphash(fp, MockTypeResultSchema()) is None


def test_get_tlsh():
    assert get_tlsh(b'foobar') is None  # make sure the result is not 'TNULL'
    assert get_tlsh(os.urandom(2**7)) not in [None, '']  # the new tlsh version should work for smaller inputs
