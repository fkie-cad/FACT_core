# pylint: disable=wrong-import-order

import logging
import os
from pathlib import Path

import pytest

from analysis.YaraPluginBase import YaraBasePlugin, _parse_meta_data, _split_output_in_rules_and_matches
from helperFunctions.fileSystem import get_src_dir
from objects.file import FileObject
from test.common_helper import get_test_data_dir

YARA_TEST_OUTPUT = Path(get_test_data_dir(), 'yara_matches').read_text()


class YaraPlugin(YaraBasePlugin):
    FILE = '/foo/bar/Yara_Base_Plugin/code/test.py'


@pytest.mark.AnalysisPluginClass.with_args(YaraPlugin)
class TestAnalysisYaraBasePlugin:
    def test_get_signature_paths(self, analysis_plugin):
        intended_signature_path = os.path.join(get_src_dir(), 'analysis/signatures', analysis_plugin.NAME)
        assert isinstance(analysis_plugin.signature_path, str), 'incorrect type'
        assert f'{intended_signature_path.rstrip("/")}.yc' == analysis_plugin.signature_path, 'signature path is wrong'

    def test_process_object(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(get_test_data_dir(), 'yara_test_file'))
        test_file.processed_analysis.update({analysis_plugin.NAME: []})
        processed_file = analysis_plugin.process_object(test_file)
        results = processed_file.processed_analysis[analysis_plugin.NAME]
        assert len(results) == 2, 'not all matches found'
        assert 'testRule' in results, 'testRule match not found'
        assert results['summary'] == ['testRule']

    def test_process_object_nothing_found(self, analysis_plugin):
        test_file = FileObject(file_path=os.path.join(get_test_data_dir(), 'zero_byte'))
        test_file.processed_analysis.update({analysis_plugin.NAME: []})
        processed_file = analysis_plugin.process_object(test_file)
        assert len(processed_file.processed_analysis[analysis_plugin.NAME]) == 1, 'result present but should not'
        assert processed_file.processed_analysis[analysis_plugin.NAME]['summary'] == [], 'summary not empty'


def test_parse_yara_output():
    matches = YaraBasePlugin._parse_yara_output(YARA_TEST_OUTPUT)  # pylint: disable=protected-access

    assert isinstance(matches, dict), 'matches should be dict'
    assert 'PgpPublicKeyBlock' in matches, 'Pgp block should have been matched'
    assert matches['PgpPublicKeyBlock']['strings'][0][0] == 0, 'first block should start at 0x0'
    assert 'r_libjpeg8_8d12b1_0' in matches
    assert matches['r_libjpeg8_8d12b1_0']['meta']['description'] == 'foo [bar]'
    assert len(matches) == 7, 'not all matches found'


def test_get_signature_file_name():
    assert (
        YaraBasePlugin._get_signature_file_name('/foo/bar/plugin_name/code/test.py') == 'plugin_name.yc'
    )  # pylint: disable=protected-access


def test_parse_meta_data_error(caplog):
    with caplog.at_level(logging.WARNING):
        _parse_meta_data('illegal,meta,entry')
        assert 'Malformed meta' in caplog.messages[0]


def test_split_output_uneven():
    uneven_yara_output = 'rule1 [meta=0,data=1] /path\n0x0:$a1: AA BB \nrule2 [meta=0,data=1] /path\n'
    with pytest.raises(ValueError):
        _split_output_in_rules_and_matches(uneven_yara_output)
