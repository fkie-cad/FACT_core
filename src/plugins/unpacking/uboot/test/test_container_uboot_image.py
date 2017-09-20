import unittest
import os

from ..internal.uboot_container import uBootHeader


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestUbootImage(unittest.TestCase):

    def setUp(self):
        self.test_firmware = os.path.join(TEST_DATA_DIR, 'uboot.image_with_header')

    def test_header(self):
        expected_image_size = 32753
        expected_arch = 5
        expected_os = 5
        expected_image_type = 5
        expected_image_name = 'u-boot image'
        expected_crc32 = 0x385a8513

        ubh = uBootHeader()
        with open(self.test_firmware, 'r+b') as uboot_image:
            ubh.create_from_binary(uboot_image.read(64))
        self.assertEqual(expected_image_size, ubh.image_data_size)
        self.assertEqual(expected_arch, ubh.cpu_architecture)
        self.assertEqual(expected_os, ubh.operating_system)
        self.assertEqual(expected_image_type, ubh.image_type)
        self.assertEqual(expected_image_name, ubh.image_name)
        self.assertEqual(expected_crc32, ubh.image_data_crc)
