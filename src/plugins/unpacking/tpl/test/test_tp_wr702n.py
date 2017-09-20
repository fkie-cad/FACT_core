import os

from common_helper_files import get_binary_from_file

from helperFunctions.hash import get_sha256
from test.unit.unpacker.test_unpacker import TestUnpackerBase
from ..code.TPWRN702N import TPWR702N

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestTpWr702n(TestUnpackerBase):
    def setUp(self):
        super().setUp()

        self.test_firmware = os.path.join(TEST_DATA_DIR, 'wr.fw')
        self.firmware_container = TPWR702N(self.test_firmware)

    def tearDown(self):
        self.ds_tmp_dir.cleanup()
        self.tmp_dir.cleanup()

    def test_unpacker_selection(self):
        self.check_unpacker_selection('firmware/tp-wr702n', 'TP-WR702N')

    def test_get_meta_dict(self):
        expected_meta_data = {'bootloader_offset': 26820,
                              'img0': {'device_id': '0x0702',
                                       'language': 'English',
                                       'language_code': '0x1101',
                                       'size': 1539104,
                                       'sub_header': {'device_id': '0x0702',
                                                      'language': 'English',
                                                      'language_code': '0x1101',
                                                      'size': 1276832}},
                              'md5': 'a1ea03bf7466517aa545779640e01acd',
                              'os_offset': 262420,
                              'uncarved_area': [(0, 1539124)]}

        self.assertEqual(expected_meta_data, self.firmware_container.get_meta_dict())

    def test_header_and_binary(self):
        self.unpacker.extract_files_from_file(self.test_firmware, self.tmp_dir.name)
        expected_files_with_hash = {'container_header.hdr': '446d194c0e5beeccf9cd1534205cbeedcedf28491beaeb72d85e485f61071e0a',
                                    'img0.hdr': '311c4a4f4c3c7b097c9419c58fe245bf2e2f7cedbaf3017870f34242a49b16b5',
                                    'bootloader.7z': 'b4fa4a19502b82ea5984c8ee24396873e710c157adeafebd4bd3e51f40d5cf9f',
                                    'main.img': '9af7e4f50e0220f8b38246b3f7d790b5078f6f049c2d35272ce5edb9a06464e9',
                                    'main.7z': '099491872fcab8a4f05f18f1e3566150f3049bf1f3d9d6354437e5e371251e66',
                                    'main.owfs': 'c14d965a60f1b388120695951fed05425e025af6f204332ea2eeca5b9427065d'}

        for expected in expected_files_with_hash:
            self._hash_compare(expected, expected_files_with_hash[expected])

    def _hash_compare(self, filename, hashsum):
        binary_data = get_binary_from_file(os.path.join(self.tmp_dir.name, filename))
        self.assertEqual(get_sha256(binary_data), hashsum, 'Checksum incorrect for file {}'.format(filename))

    def test_extraction(self):
        in_file = self.test_firmware
        files, meta_data = self.unpacker.extract_files_from_file(in_file, self.tmp_dir.name)

        expected_container_header = 1
        expected_img0_header = 1
        expected_bootloader = 1
        expected_main = 1
        expected_os = 1
        expected_fs = 1
        expected_remaining = 2

        self.assertEqual(len(files),
                         expected_remaining + expected_container_header + expected_bootloader + expected_main + expected_os + expected_fs + expected_img0_header,
                         'file number incorrect')
