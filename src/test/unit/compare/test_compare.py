# pylint: disable=wrong-import-order,protected-access,no-self-use,unused-argument
import gc
import unittest

import pytest

from compare.compare import Compare
from compare.PluginBase import CompareBasePlugin
from helperFunctions.hash import get_ssdeep
from test.common_helper import create_test_file_object, create_test_firmware


@pytest.fixture(autouse=True)
def no_compare_views(monkeypatch):
    monkeypatch.setattr(CompareBasePlugin, '_sync_view', value=lambda s, p: None)


class MockDbInterface:
    def __init__(self):
        self.fw = create_test_firmware()
        self.fo = create_test_file_object()
        self.fo.processed_analysis['file_hashes'] = {'ssdeep': get_ssdeep(self.fo.binary)}
        self.fw.add_included_file(self.fo)
        self.fw.processed_analysis['file_hashes'] = {'ssdeep': get_ssdeep(self.fw.binary)}

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


class TestCompare(unittest.TestCase):
    def setUp(self):
        self.fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
        self.fw_one.processed_analysis['file_hashes'] = {'ssdeep': get_ssdeep(self.fw_one.binary)}
        self.fw_two = create_test_firmware(
            device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True
        )
        self.fw_two.processed_analysis['file_hashes'] = {'ssdeep': get_ssdeep(self.fw_two.binary)}
        self.compare_system = Compare(db_interface=MockDbInterface())

    def tearDown(self):
        gc.collect()

    def test_compare_objects(self):
        result = self.compare_system.compare_objects([self.fw_one, self.fw_two])
        assert isinstance(result, dict), 'Result is not a dict'
        assert 'general' in result, 'general part is missing'
        assert isinstance(result['general'], dict), 'general part is not a dict'
        assert 'plugins' in result, 'plugin part is missing'
        assert isinstance(result['plugins'], dict), 'plugins part is not a dict'

    def test_compare_error_none_existing_fo(self):
        with pytest.raises(AttributeError):
            self.compare_system.compare(['error'])

    def test_create_general_section_dict(self):
        result = self.compare_system._create_general_section_dict([self.fw_one, self.fw_two])
        assert isinstance(result, dict), 'result is not a dict'
        assert result['device_name'][self.fw_one.uid] == 'dev_1'
        assert result['device_name'][self.fw_two.uid] == 'dev_2'
        assert result['device_class'][self.fw_one.uid] == 'Router'
        assert result['vendor'][self.fw_one.uid] == 'test_vendor'
        assert result['version'][self.fw_one.uid] == '0.1'
        assert result['release_date'][self.fw_one.uid] == '1970-01-01'
        assert result['size'][self.fw_one.uid] == len(self.fw_one.binary)
        assert result['virtual_file_path'][self.fw_one.uid] == [self.fw_one.uid]

    def test_plugin_system(self):
        assert len(self.compare_system.compare_plugins) > 0, 'no compare plugin found'
        assert 'File_Coverage' in self.compare_system.compare_plugins, 'File Coverage module not found'
