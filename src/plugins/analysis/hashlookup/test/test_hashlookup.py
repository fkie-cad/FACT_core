# pylint: disable=redefined-outer-name,unused-argument,protected-access,wrong-import-order
import pytest

from test.common_helper import create_test_file_object, get_config_for_testing

from ..code.hashlookup import AnalysisPlugin

KNOWN_ZSH_HASH = 'A6F2177402114FC8B5E7ECF924FFA61A2AC25BD347BC3370FB92E07B76E0B44C'


class MockAdmin:
    def register_plugin(self, name, administrator):
        pass


@pytest.fixture(scope='function')
def test_config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def stub_plugin(test_config, monkeypatch):
    monkeypatch.setattr('plugins.base.BasePlugin._sync_view', lambda self, plugin_path: None)
    return AnalysisPlugin(MockAdmin(), test_config, offline_testing=True)


def test_process_object_unknown_hash(stub_plugin, monkeypatch):
    test_file = create_test_file_object()
    test_file.processed_analysis['file_hashes'] = {'sha256': test_file.sha256}
    monkeypatch.setattr('storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_file.file_path)
    stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert 'message' in result
    assert 'sha256 hash unknown' in result['message']


def test_process_object_known_hash(stub_plugin, monkeypatch):
    test_file = create_test_file_object()
    test_file.processed_analysis['file_hashes'] = {'sha256': KNOWN_ZSH_HASH}
    monkeypatch.setattr('storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_file.file_path)
    stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert 'FileName' in result
    assert result['FileName'] == './bin/zsh'


def test_process_object_missing_hash(stub_plugin, monkeypatch):
    test_file = create_test_file_object()
    monkeypatch.setattr('storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_file.file_path)
    stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert 'message' in result
    assert result['message'].startswith('Lookup needs sha256 hash')
