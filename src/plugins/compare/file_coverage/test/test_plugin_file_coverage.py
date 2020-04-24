# pylint: disable=protected-access,no-member
import pytest

from plugins.compare.file_coverage.code.file_coverage import ComparePlugin, generate_similarity_sets
from test.unit.compare.compare_plugin_test_class import ComparePluginTest


class DbMock:  # pylint: disable=unused-argument,no-self-use
    def __init__(self, config):
        pass

    def get_entropy(self, uid):
        return 0.2

    def get_ssdeep_hash(self, uid):
        return '42'


class TestComparePluginFileCoverage(ComparePluginTest):

    # This name must be changed according to the name of plug-in to test
    PLUGIN_NAME = 'File_Coverage'

    def setup_plugin(self):
        '''
        This function must be overwritten by the test instance.
        In most cases it is sufficient to copy this function.
        '''
        return ComparePlugin(self, config=self.config, db_interface=DbMock(None), plugin_path=None)

    def test_get_intersection_of_files(self):
        self.fw_one.list_of_all_included_files.append('foo')
        self.fw_two.list_of_all_included_files.append('foo')
        result = self.c_plugin._get_intersection_of_files([self.fw_one, self.fw_two])
        self.assertIsInstance(result, dict, 'result is not a dict')
        self.assertIn('all', result, 'all field not present')
        self.assertEqual(result['all'], ['foo'], 'intersection not correct')

    def test_get_exclusive_files(self):
        result = self.c_plugin._get_exclusive_files([self.fw_one, self.fw_two])
        self.assertIsInstance(result, dict, 'result is not a dict')
        self.assertIn(self.fw_one.uid, result, 'fw_one entry not found in result')
        self.assertIn(self.fw_two.uid, result, 'fw_two entry not found in result')
        self.assertIn(self.fw_one.uid, result[self.fw_one.uid], 'fw_one not exclusive to one')
        self.assertNotIn(self.fw_two.uid, result[self.fw_one.uid], 'fw_two in exclusive file of fw one')

    def test_get_files_in_more_than_one_but_not_in_all(self):
        self.fw_one.list_of_all_included_files.append('foo')
        self.fw_two.list_of_all_included_files.append('foo')
        fo_list = [self.fw_one, self.fw_two, self.fw_three]
        tmp_result_dict = {'files_in_common': {}, 'exclusive_files': {}}
        tmp_result_dict['files_in_common']['all'] = set()
        for fo in fo_list:
            tmp_result_dict['exclusive_files'][fo.uid] = fo.uid
        result = self.c_plugin._get_files_in_more_than_one_but_not_in_all(fo_list, tmp_result_dict)
        self.assertIsInstance(result, dict, 'result is not a dict')
        self.assertIn('foo', result[self.fw_one.uid], 'foo not in result fw one')
        self.assertIn('foo', result[self.fw_two.uid], 'foo not in result fw_two')
        self.assertNotIn('foo', result[self.fw_three.uid], 'foo in result fw_three')

    def test_run_compare_plugin(self):
        self.fw_one.list_of_all_included_files.append('foo')
        self.fw_two.list_of_all_included_files.append('foo')
        result = self.c_plugin.compare_function([self.fw_one, self.fw_two])
        self.assertCountEqual(result.keys(), ['similar_files', 'exclusive_files', 'files_in_common', 'non_zero_files_in_common'])


@pytest.mark.parametrize('similar_files, similarity_dict, expected_output', [
    (['fw1:file1', 'fw2:file2'], {}, ''),
    (['fw1:file1', 'fw2:file2'], {'fw1:file1;fw2:file2': '99'}, '99'),
    (['fw1:file1', 'fw2:file2', 'fw2:file3'], {'fw1:file1;fw2:file2': '99'}, '99'),
    (
        ['fw1:file1', 'fw2:file2', 'fw3:file3'],
        {'fw1:file1;fw2:file2': '80', 'fw2:file2;fw3:file3': '90'},
        '80 ‒ 90'
    ),
    (
        ['fw1:file1', 'fw2:file2', 'fw3:file3'],
        {'fw1:file1;fw2:file2': '70', 'fw1:file1;fw3:file3': '80', 'fw2:file2;fw3:file3': '90'},
        '70 ‒ 90'
    ),
])
def test_get_similarity_value(similar_files, similarity_dict, expected_output):
    assert ComparePlugin._get_similarity_value(similar_files, similarity_dict) == expected_output


@pytest.mark.parametrize('test_input, expected_output', [
    ([], []),
    ([(1, 2), (2, 3), (1, 3)], [[1, 2, 3]]),
    ([(1, 2), (2, 3), (1, 3), (1, 4), (2, 4), (3, 4), (1, 5), (2, 5), (3, 5), (4, 5)], [[1, 2, 3, 4, 5]]),
    ([(1, 2), (2, 3), (1, 3), (1, 4)], [[1, 2, 3], [1, 4]]),
    ([(1, 2), (2, 3), (1, 3), (1, 4), (3, 4)], [[1, 2, 3], [1, 3, 4]]),
    ([(1, 4), (4, 5)], [[1, 4], [4, 5]]),
])
def test_generate_similarity_sets(test_input, expected_output):
    assert generate_similarity_sets(test_input) == expected_output
