# pylint: disable=redefined-outer-name,unused-argument,protected-access,wrong-import-order

from pathlib import Path

import pytest

from test.common_helper import CommonDatabaseMock, create_test_file_object, get_config_for_testing
from test.mock import mock_patch

from ..code.source_code_analysis import AnalysisPlugin

PYLINT_TEST_FILE = Path(__file__).parent / 'data' / 'linter_test_file'


@pytest.fixture(scope='function')
def test_config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def test_object():
    return create_test_file_object()


@pytest.fixture(scope='function')
def stub_plugin(test_config, monkeypatch):
    return AnalysisPlugin(test_config, offline_testing=True, view_updater=CommonDatabaseMock())


def test_process_object_not_supported(stub_plugin, test_object, monkeypatch):
    monkeypatch.setattr(
        'storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_object.file_path
    )
    result = stub_plugin.process_object(test_object)
    assert result.processed_analysis[stub_plugin.NAME] == {
        'summary': [],
        'warning': 'Is not a script or language could not be detected',
    }


def test_process_object_this_file(stub_plugin, monkeypatch):
    test_file = create_test_file_object(bin_path=str(PYLINT_TEST_FILE))
    with mock_patch(stub_plugin._fs_organizer, 'generate_path_from_uid', lambda _: test_file.file_path):
        stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert result['full']
    assert result['full'][0]['type'] == 'warning'
    assert result['full'][0]['symbol'] == 'unused-import'


def test_process_object_no_issues(stub_plugin, test_object, monkeypatch):
    test_object.processed_analysis['file_type'] = {'full': 'anything containing python'}
    monkeypatch.setattr(
        'storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_object.file_path
    )
    monkeypatch.setattr(
        'plugins.analysis.linter.code.source_code_analysis.linters.run_pylint', lambda self, file_path: []
    )
    stub_plugin.process_object(test_object)
    result = test_object.processed_analysis[stub_plugin.NAME]
    assert 'full' not in result
