from pathlib import Path

from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = Path(Path(__file__).parent, 'data')


class TestDahuaUnpacker(TestUnpackerBase):

    def test_unpacker_selection(self):
        self.check_unpacker_selection('firmware/dahua', 'dahua')

    def test_extraction(self):
        input_file = Path(TEST_DATA_DIR, 'dh.bin')
        unpacked_files, meta_data = self.unpacker.extract_files_from_file(str(input_file), self.tmp_dir.name)

        self.assertIn('zip header fixed', meta_data['output'])
        self.assertEqual(len(unpacked_files), 1)
        self.assertIn('{}/dahua_firmware.zip'.format(self.tmp_dir.name), unpacked_files)
        self.assertEqual(input_file.stat().st_size, Path(unpacked_files[0]).stat().st_size, 'file size should not change')
