# pylint: disable=redefined-outer-name,unused-argument,protected-access,wrong-import-order
import pytest

from test.common_helper import create_test_file_object

from ..code.hashlookup import AnalysisPlugin

KNOWN_ZSH_HASH = 'A6F2177402114FC8B5E7ECF924FFA61A2AC25BD347BC3370FB92E07B76E0B44C'


@pytest.fixture(scope='function')
def file_object(monkeypatch):
    test_file = create_test_file_object()
    monkeypatch.setattr('storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_file.file_path)
    return test_file


@pytest.mark.AnalysisPluginClass.with_args(AnalysisPlugin)
class TestHashlookup:
    def test_process_object_unknown_hash(self, analysis_plugin, file_object):
        file_object.processed_analysis['file_hashes'] = {'sha256': file_object.sha256}
        analysis_plugin.process_object(file_object)
        result = file_object.processed_analysis[analysis_plugin.NAME]
        assert 'message' in result
        assert 'sha256 hash unknown' in result['message']

    def test_process_object_known_hash(self, analysis_plugin, file_object):
        file_object.processed_analysis['file_hashes'] = {'sha256': KNOWN_ZSH_HASH}
        analysis_plugin.process_object(file_object)
        result = file_object.processed_analysis[analysis_plugin.NAME]
        assert 'FileName' in result
        assert result['FileName'] == './bin/zsh'

    def test_process_object_missing_hash(self, analysis_plugin, file_object):
        analysis_plugin.process_object(file_object)
        result = file_object.processed_analysis[analysis_plugin.NAME]
        assert 'failed' in result
        assert result['failed'].startswith('Lookup needs sha256 hash')
