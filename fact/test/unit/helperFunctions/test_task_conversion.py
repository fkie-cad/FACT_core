import unittest

import pytest

from fact.helperFunctions import tag
from fact.helperFunctions.task_conversion import (
    _get_tag_list,
    _get_uid_of_analysis_task,
    check_for_errors,
    convert_analysis_task_to_fw_obj,
)
from fact.objects.firmware import Firmware

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
    'uid': '2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c_14',
}


@pytest.mark.parametrize(('input_data', 'expected'), [('', []), ('a,b', ['a', 'b'])])
def test_get_tag_list(input_data, expected):
    assert _get_tag_list(input_data) == expected


class TestTaskConversion(unittest.TestCase):
    def test_check_for_errors(self):
        valid_request = {'a': 'some', 'b': 'some data'}
        assert len(check_for_errors(valid_request)) == 0, 'errors found but all entries are valid'
        invalid_request = {'a': 'some_data', 'b': None}
        result = check_for_errors(invalid_request)
        assert len(result) == 1, 'number of invalid fields not correct'
        assert result['b'] == 'Please specify the b'

    def test_get_uid_of_analysis_task(self):
        analysis_task = {'binary': b'this is a test'}
        assert (
            _get_uid_of_analysis_task(analysis_task)
            == '2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c_14'
        ), 'result is not a uid'

    def test_convert_analysis_task_to_firmware_object(self):
        fw_obj = Firmware()
        fw_obj.tags = {'tag', tag.TagColor.GRAY}
        fw_obj = convert_analysis_task_to_fw_obj(TEST_TASK)
        assert isinstance(fw_obj, Firmware), 'return type not correct'
        assert (
            fw_obj.uid == '2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c_14'
        ), 'uid not correct -> binary not correct'
        assert fw_obj.file_name == 'test_file_name'
        assert fw_obj.device_name == 'test device'
        assert fw_obj.part == 'kernel'
        assert fw_obj.device_class == 'test class'
        assert fw_obj.version == '1.0'
        assert fw_obj.vendor == 'test vendor'
        assert fw_obj.release_date == '01.01.1970'
        assert len(fw_obj.scheduled_analysis) == 2  # noqa: PLR2004
        assert 'dummy' in fw_obj.scheduled_analysis
        assert isinstance(fw_obj.tags, dict), 'tag type not correct'
        assert list(fw_obj.tags.keys()) == ['a', 'b'], 'tags not correct'
