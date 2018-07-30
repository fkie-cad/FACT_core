import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestDebUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('application/vnd.debian.binary-package', 'Deb')

    def test_extraction(self):
        files, meta_data = self.unpacker.extract_files_from_file(os.path.join(TEST_DATA_DIR, 'test.deb'), self.tmp_dir.name)

        self.assertEqual(len(files), 3, 'file number incorrect')
        self.assertIn('./usr/bin/test_elf_sfx', meta_data['output'])
