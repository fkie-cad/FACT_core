from pathlib import Path
from test.unit.unpacker.test_unpacker import TestUnpackerBase

from common_helper_files import get_binary_from_file

TEST_DATA_DIR = Path(Path(__file__).parent, 'data')


class TestHpPJL(TestUnpackerBase):

    def test_unpacker_selection(self):
        self.check_unpacker_selection('firmware/hp-pjl', 'PJL')

    def test_extraction_old_container_format(self):
        input_file = Path(TEST_DATA_DIR, 'hp_container.pjl')
        _, meta_data = self.unpacker.extract_files_from_file(str(input_file), self.tmp_dir.name)
        assert 'pjl_commands' in meta_data
        assert len(meta_data['pjl_commands']) == 17
        assert meta_data['pjl_commands'][0]['raw'] == b'@PJL JOB'

        assert Path(self.tmp_dir.name, 'HP_Color_LaserJet_CP4525.bin').exists()
        assert Path(self.tmp_dir.name, 'HP_Color_LaserJet_CP4525_dsk_ColorIQ.bin').exists()

    def test_extraction_new_container_format(self):
        input_file = Path(TEST_DATA_DIR, 'hp_new_container.pjl')
        _, meta_data = self.unpacker.extract_files_from_file(str(input_file), self.tmp_dir.name)
        assert len(meta_data) > 1
        assert Path(self.tmp_dir.name, 'fingerprint.txt').exists()

        extracted_file_path = Path(self.tmp_dir.name, '812.bin')
        assert extracted_file_path.exists()
        binary_content = get_binary_from_file(str(extracted_file_path))
        assert binary_content[0:4] == b'\x94\x1E\x12\x00'
        assert len(binary_content) == 224
