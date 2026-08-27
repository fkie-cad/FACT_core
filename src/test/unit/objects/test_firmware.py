import pytest

from objects.firmware import Firmware
from test.common_helper import create_test_firmware, get_test_data_dir


@pytest.mark.parametrize(('input_data', 'expected_count'), [(['a'], 1), (['a', 'b', 'a'], 2)])
def test_add_tag(input_data, expected_count):
    test_object = create_test_firmware()
    test_object.tags = {}
    for item in input_data:
        test_object.set_tag(item)
    for item in input_data:
        assert item in test_object.tags
    assert len(test_object.tags.keys()) == expected_count


@pytest.mark.parametrize(('input_data', 'expected_output'), [('complete', ''), ('some_part', 'some_part')])
def test_set_part_name(input_data, expected_output):
    test_object = create_test_firmware()
    test_object.set_part_name(input_data)
    assert test_object.part == expected_output


def test_create_firmware_from_file():
    test_object = Firmware.from_path(get_test_data_dir() / 'test_data_file.bin')
    assert test_object.device_name is None
    assert test_object.size == 19
    assert test_object.sha256 == '268d870ffa2b21784e4dc955d8e8b8eb5f3bcddd6720a1e6d31d2cf84bd1bff8'
    assert test_object.file_name == 'test_data_file.bin'


@pytest.mark.parametrize(
    ('input_data', 'expected_output'),
    [('complete', 'foo test_device v. 1.0'), ('some_part', 'foo test_device - some_part v. 1.0')],
)
def test_get_hid(input_data, expected_output):
    test_fw = create_test_firmware()
    test_fw.device_name = 'test_device'
    test_fw.vendor = 'foo'
    test_fw.version = '1.0'
    test_fw.set_part_name(input_data)
    assert test_fw.get_hid() == expected_output


def test_repr_and_str():
    test_fw = create_test_firmware()
    test_fw.scheduled_analysis = ['test']
    assert 'test_vendor test_router v. 0.1' in test_fw.__str__()
    assert 'test' in test_fw.__str__()
    assert test_fw.__str__() == test_fw.__repr__()
