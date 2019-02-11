from pathlib import Path
from test.unit.unpacker.test_unpacker import TestUnpackerBase

from common_helper_files.fail_safe_file_operations import get_binary_from_file

TEST_DATA_DIR = Path(Path(__file__).parent, 'data')


class TestRawUnpacker(TestUnpackerBase):

    def test_unpacker_selection(self):
        self.check_unpacker_selection('data/raw', 'RAW')

    def test_extraction(self):
        input_file = Path(TEST_DATA_DIR, 'raw.bin')
        unpacked_files, meta_data = self.unpacker.extract_files_from_file(str(input_file), self.tmp_dir.name)
        self.assertEqual(meta_data['number_of_ff_padded_sections'], 3)
        self.assertEqual(meta_data['number_of_lzma_streams'], 1)
        self.assertEqual(len(unpacked_files), 4)
        self.assertIn('{}/0x2f'.format(self.tmp_dir.name), unpacked_files)
        self.assertIn('{}/0x8d_lzma_decompressed'.format(self.tmp_dir.name), unpacked_files)
        decompressed_data = get_binary_from_file('{}/0x8d_lzma_decompressed'.format(self.tmp_dir.name))
        self.assertEqual(decompressed_data, b'compressed_stream_data')
