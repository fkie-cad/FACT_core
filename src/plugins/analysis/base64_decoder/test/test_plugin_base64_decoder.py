import os

from common_helper_files import get_dir_of_file

from helperFunctions.dataConversion import remove_linebreaks_from_byte_string
from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.base64_decoder import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class TestAnalysisPluginBase64Decoder(AnalysisPluginTest):
    PLUGIN_NAME = "base64_decoder"

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        config[self.PLUGIN_NAME]['base64_section_min_length'] = '20'
        config[self.PLUGIN_NAME]['string_min_length'] = '15'
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()

    def test_index_of_pattern_in_section(self):
        string = 'abcd.efgh.abcd.efgh.qrst.uvwx.qrst.uvwx'
        self.assertEqual(self.analysis_plugin.index_of_start_pattern_in_section(string, 'abcdefgh', 0, 20), 0, 'Subpattern in Substring is not found correctly')
        self.assertEqual(self.analysis_plugin.index_of_end_pattern_in_section(string, 'qrstuvwx', 16, 23), 30, 'Subpattern in Substring is not found correctly')
        string = 'ab.cdef.ghijkl.mnopqrst.uv'
        self.assertEqual(self.analysis_plugin.index_of_start_pattern_in_section(string, 'abcdef', 0, 14), 0, 'Subpattern in Substring is not found correctly')
        self.assertEqual(self.analysis_plugin.index_of_end_pattern_in_section(string, 'qrstuv', 14, 26), 19, 'Subpattern in Substring is not found correctly')
        string = 'ab.cd.ef.gh.ij.kl.mn.op.qr.st.uv'
        self.assertEqual(self.analysis_plugin.index_of_start_pattern_in_section(string, 'abcdef', 0, 16), None, 'Subpattern in Substring is not found correctly')
        self.assertEqual(self.analysis_plugin.index_of_end_pattern_in_section(string, 'qrstuv', 16, 32), None, 'Subpattern in Substring is not found correctly')

    def test_words_in_strings(self):
        result = self.analysis_plugin.words_in_strings(b'Will have MORE from yOuR information\x00Another free string about homepage search', self.analysis_plugin.load_word_list(), 10)
        self.assertEqual(result, (17, ['Another free string about homepage search', 'Will have MORE from yOuR information']), 'Words in strings are not found correctly.')

    def test_load_word_list(self):
        self.assertEqual(self.analysis_plugin.load_word_list()[0:3], ['noel', 'anon', 'free'], 'Word list is not read correctly')

    def test_remove_linebreaks(self):
        self.assertEqual(remove_linebreaks_from_byte_string(b'abcd'), (b'abcd', 0), 'Linebreaks are not removed correctly')
        self.assertEqual(remove_linebreaks_from_byte_string(b'abcd\x0a'), (b'abcd', 1), 'Linebreaks are not removed correctly')
        self.assertEqual(remove_linebreaks_from_byte_string(b'abcd\x0d'), (b'abcd', 1), 'Linebreaks are not removed correctly')
        self.assertEqual(remove_linebreaks_from_byte_string(b'abcd\x0a\x0d'), (b'abcd', 2), 'Linebreaks are not removed correctly')
        self.assertEqual(remove_linebreaks_from_byte_string(b'abcd\x0a\x0defgh'), (b'abcdefgh', 2), 'Linebreaks are not removed correctly')

    def test_find_base64_sections(self):
        self.assertEqual(self.helper_find_base64_sections(b'ab', 8), [], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcd', 4), [b'abcd'], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcd', 8), [], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcde', 8), [], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcdef', 8), [], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcdefg', 8), [], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcdefgh', 8), [b'abcdefgh'], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcdefg=', 8), [b'abcdefg='], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcdef==', 8), [b'abcdef=='], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcdefghij=', 8), [b'abcdefghij='], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcdefgh+/=', 8), [b'abcdefgh+/='], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections2(b'abcdefgh+/=', 8, '+/'), [b'abcdefgh+/='], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections2(b'abcdefgh_-=', 8, '-_'), [b'abcdefgh_-='], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcdefgh ijklmnop=', 8), [b'abcdefgh', b'ijklmnop='], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcde fghijklm', 8), [b'fghijklm'], 'Base64 sections are not found correctly')
        self.assertEqual(self.helper_find_base64_sections(b'abcde fghij=abcd', 8), [], 'Base64 sections are not found correctly')

    def test_generate_valid_base64_matches(self):
        generator = self.analysis_plugin.generate_valid_base64_matches(b'abcdefgh')
        self.assertEqual([match for match in generator],
                         [((0, 8, 0), b'abcdefgh'), ((1, 5, 3), b'bcde'), ((2, 6, 2), b'cdef'), ((3, 7, 1), b'defg')], 'Valid base64 matches are not generated correctly')
        generator = self.analysis_plugin.generate_valid_base64_matches(b'abcdefghi')
        self.assertEqual([match for match in generator],
                         [((0, 8, 1), b'abcdefgh'), ((1, 9, 0), b'bcdefghi'), ((2, 6, 3), b'cdef'), ((3, 7, 2), b'defg')], 'Valid base64 matches are not generated correctly')
        generator = self.analysis_plugin.generate_valid_base64_matches(b'abcdefghij')
        self.assertEqual([match for match in generator],
                         [((0, 8, 2), b'abcdefgh'), ((1, 9, 1), b'bcdefghi'), ((2, 10, 0), b'cdefghij'), ((3, 7, 3), b'defg')], 'Valid base64 matches are not generated correctly')
        generator = self.analysis_plugin.generate_valid_base64_matches(b'abcdefghijk')
        self.assertEqual([match for match in generator],
                         [((0, 8, 3), b'abcdefgh'), ((1, 9, 2), b'bcdefghi'), ((2, 10, 1), b'cdefghij'), ((3, 11, 0), b'defghijk')], 'Valid base64 matches are not generated correctly')

    def helper_find_base64_sections(self, my_bytes, min_length):
        return [m.group(0) for m in self.analysis_plugin.find_base64_sections(my_bytes, min_length)]

    def helper_find_base64_sections2(self, my_bytes, min_length, special_characters):
        return [m.group(0) for m in self.analysis_plugin.find_base64_sections(my_bytes, min_length, special_characters)]

    def test_plugin_works_on_real_file(self):
        test_file = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'base64.test'))
        file_object = self.analysis_plugin.process_object(test_file)
        result = file_object.processed_analysis[self.analysis_plugin.NAME]
        self.assertIn('summary', result, 'summary not found')
        self.assertEqual('Base64 code detected', result['summary'][0], 'code detection did not work')
        self.assertEqual(4, len(result.keys()), 'incorrect number of matches')
