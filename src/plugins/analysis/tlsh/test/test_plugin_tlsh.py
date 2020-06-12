import pytest

from plugins.analysis.tlsh.code.tlsh import AnalysisPlugin
from test.common_helper import create_test_file_object, get_config_for_testing

HASH_0 = '9A355C07B5A614FDC5A2847046EF92B7693174A642327DBF3C88D6303F42E746B1ABE1'
HASH_1 = '0CC34B06B1B258BCC16689308A67D671AB747E5053223B3E3684F7342F56E6F1F0DAB1'

# pylint: disable=redefined-outer-name


class MockAdmin:
    def register_plugin(self, name, administrator):
        pass


class MockContext:
    def __init__(self, connected_interface, config):
        pass

    def __enter__(self):
        class ControlledInterface:
            def tlsh_query_all_objects(self):  # pylint: disable=no-self-use
                return [{'processed_analysis': {'file_hashes': {'tlsh': HASH_1}}, '_id': '5'}, ]

        return ControlledInterface()

    def __exit__(self, *args):
        pass


class EmptyContext(MockContext):
    def __enter__(self):
        class EmptyInterface:
            def tlsh_query_all_objects(self):  # pylint: disable=no-self-use
                return []

        return EmptyInterface()


@pytest.fixture(scope='function')
def test_config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def test_object():
    fo = create_test_file_object()
    fo.processed_analysis['file_hashes'] = {'tlsh': HASH_1}
    return fo


@pytest.fixture(scope='function')
def stub_plugin(test_config, monkeypatch):
    monkeypatch.setattr('plugins.base.BasePlugin._sync_view', lambda self, plugin_path: None)
    return AnalysisPlugin(MockAdmin(), test_config, offline_testing=True)


def test_one_matching_file(stub_plugin, test_object, monkeypatch):
    monkeypatch.setattr('plugins.analysis.tlsh.code.tlsh.ConnectTo', MockContext)

    result = stub_plugin.process_object(test_object)
    assert result.processed_analysis[stub_plugin.NAME] == {'5': 0}


def test_no_matching_file(test_object, stub_plugin, monkeypatch):
    monkeypatch.setattr('plugins.analysis.tlsh.code.tlsh.ConnectTo', MockContext)
    not_matching_hash = '0CC34689821658B06B1B258BCC16689308A671AB3223B3E3684F8d695A658742F0DAB1'
    test_object.processed_analysis['file_hashes'] = {'tlsh': not_matching_hash}
    result = stub_plugin.process_object(test_object)

    assert result.processed_analysis[stub_plugin.NAME] == {}


def test_match_to_same_file(test_object, stub_plugin, monkeypatch):
    monkeypatch.setattr('plugins.analysis.tlsh.code.tlsh.ConnectTo', MockContext)
    test_object.uid = '5'
    result = stub_plugin.process_object(test_object)

    assert result.processed_analysis[stub_plugin.NAME] == {}


def test_file_has_no_tlsh_hash(test_object, stub_plugin, monkeypatch):
    monkeypatch.setattr('plugins.analysis.tlsh.code.tlsh.ConnectTo', MockContext)
    test_object.processed_analysis['file_hashes'].pop('tlsh')
    result = stub_plugin.process_object(test_object)

    assert result.processed_analysis[stub_plugin.NAME] == {}


def test_no_files_in_database(test_object, stub_plugin, monkeypatch):
    monkeypatch.setattr('plugins.analysis.tlsh.code.tlsh.ConnectTo', EmptyContext)
    result = stub_plugin.process_object(test_object)

    assert result.processed_analysis[stub_plugin.NAME] == {}


def test_file_hashes_not_run(test_object, stub_plugin):
    with pytest.raises(KeyError):
        test_object.processed_analysis.pop('file_hashes')
        stub_plugin.process_object(test_object)
