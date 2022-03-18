# pylint: disable=redefined-outer-name,wrong-import-order
import pytest

from plugins.analysis.tlsh.code.tlsh import AnalysisPlugin
from test.common_helper import CommonDatabaseMock, create_test_file_object
from test.mock import mock_patch

HASH_0 = '9A355C07B5A614FDC5A2847046EF92B7693174A642327DBF3C88D6303F42E746B1ABE1'
HASH_1 = '0CC34B06B1B258BCC16689308A67D671AB747E5053223B3E3684F7342F56E6F1F0DAB1'


class MockAdmin:
    def register_plugin(self, name, administrator):
        pass


class MockDb:
    def get_all_tlsh_hashes(self):  # pylint: disable=no-self-use
        return [('test_uid', HASH_1)]


@pytest.fixture(scope='function')
def test_object():
    fo = create_test_file_object()
    fo.processed_analysis['file_hashes'] = {'tlsh': HASH_1}
    return fo


@pytest.fixture(scope='function')
def stub_plugin(monkeypatch):
    return AnalysisPlugin(
        MockAdmin(),
        offline_testing=True,
        view_updater=CommonDatabaseMock(),
        db_interface=MockDb(),
    )


def test_one_matching_file(stub_plugin, test_object):

    result = stub_plugin.process_object(test_object)
    assert result.processed_analysis[stub_plugin.NAME] == {'test_uid': 0}


def test_no_matching_file(test_object, stub_plugin):
    not_matching_hash = '0CC34689821658B06B1B258BCC16689308A671AB3223B3E3684F8d695A658742F0DAB1'
    test_object.processed_analysis['file_hashes'] = {'tlsh': not_matching_hash}
    result = stub_plugin.process_object(test_object)

    assert result.processed_analysis[stub_plugin.NAME] == {}


def test_match_to_same_file(test_object, stub_plugin):
    test_object.uid = 'test_uid'
    result = stub_plugin.process_object(test_object)

    assert result.processed_analysis[stub_plugin.NAME] == {}


def test_file_has_no_tlsh_hash(test_object, stub_plugin):
    test_object.processed_analysis['file_hashes'].pop('tlsh')
    result = stub_plugin.process_object(test_object)

    assert result.processed_analysis[stub_plugin.NAME] == {}


def test_no_files_in_database(test_object, stub_plugin):
    with mock_patch(stub_plugin.db, 'get_all_tlsh_hashes', lambda: []):
        result = stub_plugin.process_object(test_object)

    assert result.processed_analysis[stub_plugin.NAME] == {}


def test_file_hashes_not_run(test_object, stub_plugin):
    with pytest.raises(KeyError):
        test_object.processed_analysis.pop('file_hashes')
        stub_plugin.process_object(test_object)
