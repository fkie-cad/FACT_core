import os

from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestTplTool(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('firmware/tp-link', 'tpl-tool')

    def test_extraction(self):
        files, meta_data = self.unpacker.extract_files_from_file(os.path.join(TEST_DATA_DIR, 'test.tpl'), self.tmp_dir.name)
        self.assertEqual(len(files), 4)
        unpacked_files = [os.path.basename(f) for f in files]
        expected_files = ['test.tpl-rootfs', 'test.tpl-kernel', 'test.tpl-header', 'test.tpl-bootldr']
        for f in unpacked_files:
            self.assertIn(f, expected_files)
        self.assertIn('header-info', meta_data)
