# -*- coding: utf-8 -*-
import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestAmbarellaRomFSUnpacker(TestUnpackerBase):

    def test_unpacker_selection(self):
        self.check_unpacker_selection('filesystem/ambarella-romfs', 'Ambarella_RomFS')

    def test_extraction(self):
        input_file = os.path.join(TEST_DATA_DIR, 'ambarella_rom.fs')
        unpacked_files, meta_data = self.unpacker.extract_files_from_file(input_file, self.tmp_dir.name)
        self.assertIn("'file_count': 4", meta_data['output'], 'should be 4 files in the romfs')
        self.assertGreaterEqual(len(unpacked_files), 5, 'Should contain 4 files and a header')
