# pylint: disable=wrong-import-order,protected-access,unused-argument,redefined-outer-name
import pytest

from compare.compare import Compare
from compare.PluginBase import CompareBasePlugin
from test.common_helper import create_test_file_object, create_test_firmware


@pytest.fixture(autouse=True)
def _no_compare_views(monkeypatch):
    monkeypatch.setattr(CompareBasePlugin, '_sync_view', value=lambda *_: None)


class MockDbInterface:
    def __init__(self):
        self.fw = create_test_firmware()
        self.fo = create_test_file_object()
        self.fw.add_included_file(self.fo)

    def get_object(self, uid, analysis_filter=None):
        if uid == self.fw.uid:
            return self.fw
        if uid == 'error':
            return None
        return self.fo

    def get_ssdeep_hash(self, uid):
        return ''

    def get_complete_object_including_all_summaries(self, uid):
        return self.get_object(uid)

    def get_vfp_of_included_text_files(self, root_uid, blacklist=None):
        return {}

    def get_vfps_for_uid_list(self, uid_list, root_uid=None):
        return {}


@pytest.fixture()
def compare_system():
    return Compare(db_interface=MockDbInterface())


fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
fw_two = create_test_firmware(device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True)


def test_compare_objects(compare_system):
    result = compare_system.compare_objects([fw_one, fw_two])
    assert isinstance(result, dict), 'Result is not a dict'
    assert 'general' in result, 'general part is missing'
    assert isinstance(result['general'], dict), 'general part is not a dict'
    assert 'plugins' in result, 'plugin part is missing'
    assert isinstance(result['plugins'], dict), 'plugins part is not a dict'


def test_compare_error_none_existing_fo(compare_system):
    with pytest.raises(AttributeError):
        compare_system.compare(['error'])


def test_create_general_section_dict(compare_system):
    result = compare_system._create_general_section_dict([fw_one, fw_two])
    assert isinstance(result, dict), 'result is not a dict'
    assert result['device_name'][fw_one.uid] == 'dev_1'
    assert result['device_name'][fw_two.uid] == 'dev_2'
    assert result['device_class'][fw_one.uid] == 'Router'
    assert result['vendor'][fw_one.uid] == 'test_vendor'
    assert result['version'][fw_one.uid] == '0.1'
    assert result['release_date'][fw_one.uid] == '1970-01-01'
    assert result['size'][fw_one.uid] == len(fw_one.binary)
    assert result['virtual_file_path'][fw_one.uid] == [fw_one.file_name]


def test_plugin_system(compare_system):
    assert len(compare_system.compare_plugins) > 0, 'no compare plugin found'
    assert 'File_Coverage' in compare_system.compare_plugins, 'File Coverage module not found'
