import gc
import unittest

import pytest

from compare.PluginBase import CompareBasePlugin
from compare.compare import Compare
from helperFunctions.config import get_config_for_testing
from helperFunctions.hash import get_ssdeep
from test.common_helper import create_test_firmware, create_test_file_object


@pytest.fixture(autouse=True)
def no_compare_views(monkeypatch):
    monkeypatch.setattr(CompareBasePlugin, '_sync_view', value=lambda s, p: None)


class MockDbInterface(object):

    def __init__(self):
        self.fw = create_test_firmware()
        self.fo = create_test_file_object()
        self.fo.processed_analysis['file_hashes'] = {'ssdeep': get_ssdeep(self.fo.binary)}
        self.fw.add_included_file(self.fo)
        self.fw.processed_analysis['file_hashes'] = {'ssdeep': get_ssdeep(self.fw.binary)}

    def get_object(self, uid, analysis_filter=None):
        if uid == self.fw.get_uid():
            return self.fw
        elif uid == 'error':
            return None
        else:
            return self.fo


class TestCompare(unittest.TestCase):

    def setUp(self):
        self.config = get_config_for_testing()
        self.fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
        self.fw_one.processed_analysis['file_hashes'] = {'ssdeep': get_ssdeep(self.fw_one.binary)}
        self.fw_two = create_test_firmware(device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True)
        self.fw_two.processed_analysis['file_hashes'] = {'ssdeep': get_ssdeep(self.fw_two.binary)}
        self.compare_system = Compare(db_interface=MockDbInterface(), config=self.config)

    def tearDown(self):
        gc.collect()

    def test_compare_objects(self):
        result = self.compare_system.compare_objects([self.fw_one, self.fw_two])
        self.assertIsInstance(result, dict, 'Result is not a dict')
        self.assertIn('general', result, 'general part is missing')
        self.assertIsInstance(result['general'], dict, 'general part is not a dict')
        self.assertIn('plugins', result, 'plugin part is missing')
        self.assertIsInstance(result['plugins'], dict, 'plugins part is not a dict')

    def test_compare_error_none_existing_fo(self):
        result = self.compare_system.compare(['error'])
        self.assertIsInstance(result, Exception, 'result has wrong type')

    def test_create_general_section_dict(self):
        result = self.compare_system._create_general_section_dict([self.fw_one, self.fw_two])
        self.assertIsInstance(result, dict, 'result is not a dict')
        self.assertEqual(result['device_name'][self.fw_one.get_uid()], 'dev_1')
        self.assertEqual(result['device_name'][self.fw_two.get_uid()], 'dev_2')
        self.assertEqual(result['device_class'][self.fw_one.get_uid()], 'Router')
        self.assertEqual(result['vendor'][self.fw_one.get_uid()], 'test_vendor')
        self.assertEqual(result['version'][self.fw_one.get_uid()], '0.1')
        self.assertEqual(result['release_date'][self.fw_one.get_uid()], '1970-01-01')
        self.assertEqual(result['size'][self.fw_one.get_uid()], len(self.fw_one.binary))
        self.assertEqual(result['virtual_file_path'][self.fw_one.get_uid()], [self.fw_one.get_uid()])

    def test_plugin_system(self):
        self.assertGreater(len(self.compare_system.compare_plugins), 0, 'no compare plugin found')
        self.assertIn('File_Coverage', self.compare_system.compare_plugins, 'File Coverage module not found')
