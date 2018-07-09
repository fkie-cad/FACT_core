import pytest

from storage.db_interface_common import MongoInterfaceCommon


class CommonInterfaceMock(MongoInterfaceCommon):

    def __init__(self):
        pass

    def retrieve_analysis(self, sanitized_dict, analysis_filter=None):
        return {}


current_data_format = {
    '_id': 'some_UID',
    'size': 1,
    'file_name': 'name_of_the_file',
    'device_name': 'test_device',
    'device_class': 'class_of_the_device',
    'release_date': 0,
    'vendor': 'test_vendor',
    'version': '0.1',
    'processed_analysis': {},
    'files_included': [],
    'virtual_file_path': {},
    'tags': {},
    'analysis_tags': {},
    'device_part': 'bootloader'
}

old_data_format = {
    '_id': 'some_UID',
    'size': 1,
    'file_name': 'name_of_the_file',
    'device_name': 'test_device',
    'device_class': 'class_of_the_device',
    'release_date': 0,
    'vendor': 'test_vendor',
    'version': '0.1',
    'processed_analysis': {},
    'files_included': [],
    'virtual_file_path': {},
    'comment': 'some comment'
}


@pytest.mark.parametrize('input_data, expected', [
    (current_data_format, 'bootloader'),
    (old_data_format, '')
])
def test_convert_to_firmware(input_data, expected):
    test_interface = CommonInterfaceMock()
    result = test_interface._convert_to_firmware(input_data, analysis_filter=None)
    assert result.part == expected
