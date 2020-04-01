from helperFunctions.object_conversion import create_meta_dict
from test.common_helper import create_test_file_object, create_test_firmware


def test_create_meta_dict_fw():
    fw = create_test_firmware()
    meta = create_meta_dict(fw)

    assert meta['device_name'] == 'test_router'
    assert meta['device_class'] == 'Router'
    assert meta['vendor'] == 'test_vendor'
    assert meta['device_part'] == ''
    assert meta['version'] == '0.1'
    assert meta['release_date'] == '1970-01-01'
    assert meta['hid'] == 'test_vendor test_router v. 0.1'
    assert meta['size'] == 787

    assert meta['number_of_included_files'] == 0
    assert meta['included_files'] == []
    assert meta['total_files_in_firmware'] == 'unknown'

    assert len(meta.keys()) == 11


def test_create_meta_dict_fo():
    fo = create_test_file_object()
    meta = create_meta_dict(fo)

    assert meta['firmwares_including_this_file'] == ['d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62']
    assert meta['virtual_file_path'] == ['d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62']

    assert meta['number_of_included_files'] == 0

    assert len(meta.keys()) == 7
