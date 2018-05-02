from common_helper_files import get_dir_of_file
import os

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.strings import AnalysisPlugin


TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')


class TestAnalysisPlugInPrintableStrings(AnalysisPluginTest):

    PLUGIN_NAME = 'printable_strings'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        config.set(self.PLUGIN_NAME, 'min_length', '4')
        self.analysis_plugin = AnalysisPlugin(self, config=config)

        self.strings = ['first string', 'second<>_$tring!', 'third:?-+012345/\string']
        self.offsets = [(3, self.strings[0]), (21, self.strings[1]), (61, self.strings[2])]

    def tearDown(self):
        super().tearDown()

    def test_find_strings(self):
        fo = FileObject(file_path=os.path.join(TEST_DATA_DIR, 'string_find_test_file2'))
        fo = self.analysis_plugin.process_object(fo)
        results = fo.processed_analysis[self.PLUGIN_NAME]
        print(results)
        for item in self.strings:
            self.assertIn(item, results['strings'], '{} not found'.format(item))
        self.assertEqual(len(results['strings']), len(self.strings), 'number of found strings not correct')
        for item in self.offsets:
            assert item in results['offsets'], 'offset {} not found'.format(item)
        assert len(results['offsets']) == len(self.offsets), 'number of offsets not correct'

    def test_find_offsets(self):
        test_binary = b'0abc45def9ghi'
        test_string_list = ['abc', 'def', 'ghi']
        assert self.analysis_plugin._find_offsets(test_string_list, test_binary) == [(1, 'abc'), (6, 'def'), (10, 'ghi')]

    def test_find_offsets__multiple_occurrences(self):
        test_binary = b'abc345abc9abc'
        test_string_list = ['abc']
        assert self.analysis_plugin._find_offsets(test_string_list, test_binary) == [(0, 'abc'), (6, 'abc'), (10, 'abc')]
