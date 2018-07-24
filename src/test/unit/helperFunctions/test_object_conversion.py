import unittest
from test.common_helper import create_test_firmware, create_test_file_object
from helperFunctions.object_conversion import create_meta_dict


class TestHelperFunctionsObjectConversion(unittest.TestCase):

    def test_create_meta_dict_fw(self):
        fw = create_test_firmware()
        meta = create_meta_dict(fw)
        self.assertEqual(meta['device_name'], 'test_router')
        self.assertEqual(meta['device_class'], 'Router')
        self.assertEqual(meta['vendor'], 'test_vendor')
        self.assertEqual(meta['device_part'], '')
        self.assertEqual(meta['version'], '0.1')
        self.assertEqual(meta['release_date'], '1970-01-01')
        self.assertEqual(meta['hid'], 'test_vendor test_router v. 0.1')
        self.assertEqual(meta['size'], 787)
        self.assertEqual(len(meta.keys()), 8)

    def test_create_meta_dict_fo(self):
        fo = create_test_file_object()
        fo.list_of_all_included_files = []
        meta = create_meta_dict(fo)
        self.assertEqual(meta['firmwares_including_this_file'], ['d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62'])
        self.assertEqual(meta['virtual_file_path'], ['d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62'])
        self.assertEqual(meta['number_of_files'], 0)
        self.assertEqual(len(meta.keys()), 5)
