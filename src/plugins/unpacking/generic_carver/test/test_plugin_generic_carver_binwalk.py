import unittest
from test.unit.unpacker.test_unpacker import TestUnpackerBase
from helperFunctions.fileSystem import get_test_data_dir


class TestGenericCarver(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('generic/carver', 'generic_carver')

    def test_extraction(self):
        in_file = "{}/generic_carver_test".format(get_test_data_dir())
        files, meta_data = self.unpacker.extract_files_from_file(in_file, self.tmp_dir.name)
        files = set(files)
        self.assertEqual(len(files), 1, "file number incorrect")
        self.assertEqual(files, {'{}/_generic_carver_test.extracted/64.zip'.format(self.tmp_dir.name)}, "not all files found")
        self.assertIn('output', meta_data)


if __name__ == "__main__":
    unittest.main()
