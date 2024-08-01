import pytest

from fact.plugins.analysis.tlsh.code.tlsh import AnalysisPlugin
from fact.test.common_helper import create_test_file_object
from fact.test.mock import mock_patch

HASH_0 = '9A355C07B5A614FDC5A2847046EF92B7693174A642327DBF3C88D6303F42E746B1ABE1'
HASH_1 = '0CC34B06B1B258BCC16689308A67D671AB747E5053223B3E3684F7342F56E6F1F0DAB1'


class MockDb:
    def get_all_tlsh_hashes(self):
        return [('test_uid', HASH_1)]


@pytest.fixture
def test_object():
    fo = create_test_file_object()
    fo.processed_analysis['file_hashes'] = {'result': {'tlsh': HASH_1}}
    return fo


@pytest.fixture
def tlsh_plugin(analysis_plugin, monkeypatch):
    monkeypatch.setattr(analysis_plugin, 'db', MockDb())
    return analysis_plugin


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestTlsh:
    def test_one_matching_file(self, tlsh_plugin, test_object):
        result = tlsh_plugin.process_object(test_object)
        assert result.processed_analysis[tlsh_plugin.NAME] == {'test_uid': 0}

    def test_no_matching_file(self, test_object, tlsh_plugin):
        not_matching_hash = '0CC34689821658B06B1B258BCC16689308A671AB3223B3E3684F8d695A658742F0DAB1'
        test_object.processed_analysis['file_hashes'] = {'result': {'tlsh': not_matching_hash}}
        result = tlsh_plugin.process_object(test_object)

        assert result.processed_analysis[tlsh_plugin.NAME] == {}

    def test_match_to_same_file(self, test_object, tlsh_plugin):
        test_object.uid = 'test_uid'
        result = tlsh_plugin.process_object(test_object)

        assert result.processed_analysis[tlsh_plugin.NAME] == {}

    def test_file_has_no_tlsh_hash(self, test_object, tlsh_plugin):
        test_object.processed_analysis['file_hashes']['result'].pop('tlsh')
        result = tlsh_plugin.process_object(test_object)

        assert result.processed_analysis[tlsh_plugin.NAME] == {}

    def test_no_files_in_database(self, test_object, tlsh_plugin):
        with mock_patch(tlsh_plugin.db, 'get_all_tlsh_hashes', list):
            result = tlsh_plugin.process_object(test_object)

        assert result.processed_analysis[tlsh_plugin.NAME] == {}

    def test_file_hashes_not_run(self, test_object, tlsh_plugin):
        with pytest.raises(KeyError):  # noqa: PT012
            test_object.processed_analysis.pop('file_hashes')
            tlsh_plugin.process_object(test_object)
