from common_helper_files import get_binary_from_file
import unittest

from helperFunctions.fileSystem import get_test_data_dir
from objects.firmware import Firmware


class TestFirmwareObject(unittest.TestCase):

    def test_create_firmware_container_raw(self):
        test_object = Firmware()
        self.assertEqual(test_object.size, None, 'correct size')
        self.assertEqual(test_object.binary, None, 'correct binary')

    def test_create_firmware_from_file(self):
        test_object = Firmware()
        test_object.create_from_file('{}/test_data_file.bin'.format(get_test_data_dir()))
        self.assertEqual(test_object.device_name, None, 'correct device name')
        self.assertEqual(test_object.size, 19, 'correct size')
        self.assertEqual(test_object.binary, b'test string in file', 'correct binary data')
        self.assertEqual(test_object.sha256, '268d870ffa2b21784e4dc955d8e8b8eb5f3bcddd6720a1e6d31d2cf84bd1bff8', 'correct sha256')
        self.assertEqual(test_object.file_name, 'test_data_file.bin', 'correct file name')

    def test_set_binary(self):
        binary = get_binary_from_file('{}/get_files_test/testfile1'.format(get_test_data_dir()))
        md5 = 'e802ca22f6cd2d9357cf3da1d191879e'
        firmware = Firmware()
        firmware.set_binary(binary)
        self.assertEqual(firmware.md5, md5, 'correct md5 sum')

    def test_get_hid(self):
        test_fw = Firmware(binary=b'foo')
        test_fw.set_device_name('test_device')
        test_fw.set_vendor('foo')
        test_fw.set_firmware_version('1.0')
        self.assertEqual(test_fw.get_hid(), 'foo test_device - 1.0', 'hid not correct')
