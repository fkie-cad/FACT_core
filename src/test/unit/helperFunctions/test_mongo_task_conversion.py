import unittest

import pytest

from helperFunctions.mongo_task_conversion import check_for_errors, \
    get_uid_of_analysis_task, get_uploaded_file_binary, \
    convert_analysis_task_to_fw_obj, is_sanitized_entry, _get_tag_list
from objects.firmware import Firmware

TEST_TASK = {
    'binary': b'this is a test',
    'file_name': 'test_file_name',
    'device_name': 'test device',
    'device_part': 'kernel',
    'device_class': 'test class',
    'version': '1.0',
    'vendor': 'test vendor',
    'release_date': '01.01.1970',
    'requested_analysis_systems': ['file_type', 'dummy'],
    'tags': 'a,b',
    'uid': '2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c_14'
}


@pytest.mark.parametrize('input_data, expected', [
    ('', []),
    ('a,b', ['a', 'b'])
])
def test_get_tag_list(input_data, expected):
    assert _get_tag_list(input_data) == expected


class TestMongoTask(unittest.TestCase):

    def test_check_for_errors(self):
        valid_request = {'a': 'some', 'b': 'some data'}
        self.assertEqual(len(check_for_errors(valid_request)), 0, 'errors found but all entries are valid')
        invalid_request = {'a': 'some_data', 'b': None}
        result = check_for_errors(invalid_request)
        self.assertEqual(len(result), 1, 'number of invalid fields not correct')
        self.assertEqual(result['b'], 'Please specify the b')

    def test_get_uploaded_file_binary_error(self):
        self.assertEqual(get_uploaded_file_binary(None), None, 'missing upload file should lead to None')

    def test_get_uid_of_analysis_task(self):
        analysis_task = {'binary': b'this is a test'}
        self.assertEqual(get_uid_of_analysis_task(analysis_task), '2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c_14', 'result is not a uid')

    def test_convert_analysis_task_to_firmware_object(self):
        fw_obj = convert_analysis_task_to_fw_obj(TEST_TASK)
        self.assertIsInstance(fw_obj, Firmware, 'return type not correct')
        self.assertEqual(fw_obj.uid, '2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c_14', 'uid not correct -> binary not correct')
        self.assertEqual(fw_obj.file_name, 'test_file_name')
        self.assertEqual(fw_obj.device_name, 'test device')
        self.assertEqual(fw_obj.part, 'kernel')
        self.assertEqual(fw_obj.device_class, 'test class')
        self.assertEqual(fw_obj.version, '1.0')
        self.assertEqual(fw_obj.vendor, 'test vendor')
        self.assertEqual(fw_obj.release_date, '01.01.1970')
        self.assertEqual(len(fw_obj.scheduled_analysis), 2)
        self.assertIn('dummy', fw_obj.scheduled_analysis)
        self.assertIsInstance(fw_obj.tags, dict, 'tag type not correct')

    def test_is_sanitized_entry(self):
        sanitized_example = 'crypto_material_summary_81abfc7a79c8c1ed85f6b9fc2c5d9a3edc4456c4aecb9f95b4d7a2bf9bf652da_76415'
        normal_example = 'blah'
        self.assertTrue(is_sanitized_entry(sanitized_example))
        self.assertFalse(is_sanitized_entry(normal_example))
