import pytest
from common_helper_files import get_binary_from_file

from helperFunctions.tag import TagColor
from objects.firmware import Firmware
from test.common_helper import get_test_data_dir


@pytest.mark.parametrize('input_data, expected_count', [
    (['a'], 1),
    (['a', 'b', 'a'], 2)
])
def test_add_tag(input_data, expected_count):
    test_object = Firmware()
    for item in input_data:
        test_object.set_tag(item)
    for item in input_data:
        assert item in test_object.tags
    assert len(test_object.tags.keys()) == expected_count


@pytest.mark.parametrize('input_data, expected_output', [
    ('complete', ''),
    ('some_part', 'some_part')
])
def test_set_part_name(input_data, expected_output):
    test_object = Firmware()
    test_object.set_part_name(input_data)
    assert test_object.part == expected_output


@pytest.mark.parametrize('tag_set, remove_items, expected_count', [
    ({'a': TagColor.GRAY, 'b': TagColor.GREEN}, ['a'], 1),
    ({'a': TagColor.GRAY, 'b': TagColor.BLUE}, ['a', 'b', 'a'], 0)
])
def test_remove_tag(tag_set, remove_items, expected_count):
    test_fw = Firmware()
    test_fw.tags = tag_set
    for item in remove_items:
        test_fw.remove_tag(item)
    assert len(test_fw.tags.keys()) == expected_count


def test_create_firmware_container_raw():
    test_object = Firmware()
    assert test_object.size is None
    assert test_object.binary is None


def test_create_firmware_from_file():
    test_object = Firmware()
    test_object.create_from_file('{}/test_data_file.bin'.format(get_test_data_dir()))
    assert test_object.device_name is None
    assert test_object.size == 19
    assert test_object.binary == b'test string in file'
    assert test_object.sha256 == '268d870ffa2b21784e4dc955d8e8b8eb5f3bcddd6720a1e6d31d2cf84bd1bff8'
    assert test_object.file_name == 'test_data_file.bin'


def test_set_binary():
    binary = get_binary_from_file('{}/get_files_test/testfile1'.format(get_test_data_dir()))
    md5 = 'e802ca22f6cd2d9357cf3da1d191879e'
    firmware = Firmware()
    firmware.set_binary(binary)
    assert firmware.md5 == md5


@pytest.mark.parametrize('input_data, expected_output', [
    ('complete', 'foo test_device v. 1.0'),
    ('some_part', 'foo test_device - some_part v. 1.0')
])
def test_get_hid(input_data, expected_output):
    test_fw = Firmware(binary=b'foo')
    test_fw.set_device_name('test_device')
    test_fw.set_vendor('foo')
    test_fw.set_firmware_version('1.0')
    test_fw.set_part_name(input_data)
    assert test_fw.get_hid() == expected_output


def test_repr_and_str():
    test_fw = Firmware(scheduled_analysis=['test'])
    assert 'None None v. None' in test_fw.__str__()
    assert 'test' in test_fw.__str__()
    assert test_fw.__str__() == test_fw.__repr__()
