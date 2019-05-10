import pytest

from helperFunctions.config import get_config_for_testing
from plugins.analysis.tlsh.code.tlsh import AnalysisPlugin
from test.common_helper import create_test_file_object

HASH_0 = '9A355C07B5A614FDC5A2847046EF92B7693174A642327DBF3C88D6303F42E746B1ABE1'
HASH_1 = '0CC34B06B1B258BCC16689308A67D671AB747E5053223B3E3684F7342F56E6F1F0DAB1'


class MockAdmin:
    def register_plugin(self, name, administrator):
        pass


class MockContext:
    def __init__(self, connected_interface, config):
        pass

    def __enter__(self):
        class ControlledInterface:
            def tlsh_query_all_objects(self):
                return [{'processed_analysis': {'file_hashes': {'tlsh': HASH_0}}}, ]

        return ControlledInterface()

    def __exit__(self, *args):
        pass


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


def test_process_object(stub_plugin, test_object, monkeypatch):
    monkeypatch.setattr('plugins.analysis.tlsh.code.tlsh.ConnectTo', MockContext)

    result = stub_plugin.process_object(test_object)
    assert result.processed_analysis[stub_plugin.NAME] == {'summary': []}
