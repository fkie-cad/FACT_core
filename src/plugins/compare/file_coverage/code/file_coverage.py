from copy import deepcopy

from compare.PluginBase import CompareBasePlugin
from helperFunctions.compare_sets import (
    collapse_pair_of_sets, difference_of_lists, difference_of_sets,
    intersection_of_list_of_lists, make_pairs_of_sets,
    remove_duplicates_from_list_of_lists
)
from helperFunctions.dataConversion import (
    convert_uid_list_to_compare_id, list_of_lists_to_list_of_sets,
    list_of_sets_to_list_of_lists, remove_included_sets_from_list_of_sets
)
from helperFunctions.hash import (
    check_similarity_of_sets, get_ssdeep_comparison
)


class ComparePlugin(CompareBasePlugin):
    '''
    Compares file coverage
    '''

    NAME = 'File_Coverage'
    DEPENDENCIES = []

    def __init__(self, plugin_administrator, config=None, db_interface=None, plugin_path=__file__):
        super().__init__(plugin_administrator, config=config, db_interface=db_interface, plugin_path=plugin_path)
        self.ssdeep_ignore_threshold = self.config.getint('ExpertSettings', 'ssdeep_ignore')

    def compare_function(self, fo_list):
        compare_result = dict()
        compare_result['files_in_common'] = self._get_intersection_of_files(fo_list)
        compare_result['exclusive_files'] = self._get_exclusive_files(fo_list)

        self._handle_partially_common_files(compare_result, fo_list)

        for key in compare_result:
            if isinstance(compare_result[key], dict):
                compare_result[key]['collapse'] = False

        similar_files, similarity = self._get_similar_files(fo_list, compare_result['exclusive_files'])
        compare_result['similar_files'] = self.beautify_similar_files(similar_files, fo_list, similarity)

        return compare_result

    def _get_exclusive_files(self, fo_list):
        result = {}
        for i, current_element in enumerate(fo_list):
            tmp_list = deepcopy(fo_list)
            tmp_list.pop(i)
            result[current_element.uid] = difference_of_lists(current_element.list_of_all_included_files, self._get_list_of_file_lists(tmp_list))
        return result

    def _get_intersection_of_files(self, fo_list):
        intersecting_files = intersection_of_list_of_lists(self._get_list_of_file_lists(fo_list))
        result = {'all': intersecting_files}
        return result

    @staticmethod
    def _get_list_of_file_lists(fo_list):
        list_of_file_lists = []
        for item in fo_list:
            list_of_file_lists.append(item.list_of_all_included_files)
        return list_of_file_lists

    def _handle_partially_common_files(self, compare_result, fo_list):
        if len(fo_list) > 2:
            compare_result['files_in_more_than_one_but_not_in_all'] = self._get_files_in_more_than_one_but_not_in_all(fo_list, compare_result)
            not_in_all = compare_result['files_in_more_than_one_but_not_in_all']
        else:
            not_in_all = dict()
        compare_result['non_zero_files_in_common'] = self._get_non_zero_common_files(compare_result['files_in_common'], not_in_all)

    @staticmethod
    def _get_files_in_more_than_one_but_not_in_all(fo_list, result_dict):
        result = {}
        for _, current_element in enumerate(fo_list):
            result[current_element.uid] = list(difference_of_sets(
                set(current_element.list_of_all_included_files),
                [result_dict['files_in_common']['all'], result_dict['exclusive_files'][current_element.uid]]
            ))
        return result

    # ---- SSDEEP similarity ---- #

    def _get_similar_files(self, fo_list, exclusive_files):
        similars = list()
        similarity = dict()
        for index, _ in enumerate(fo_list):
            tmp_list = deepcopy(fo_list)
            parent_one = tmp_list.pop(index)
            for parent_two in tmp_list:
                for file_one in exclusive_files[parent_one.uid]:
                    for item, value in self._find_similar_file_for(file=file_one, parent_id=parent_one.uid, potential_matches=parent_two):
                        similars.append(item)
                        similarity[convert_uid_list_to_compare_id(item)] = value
        similarity_sets = self.produce_similarity_sets(remove_duplicates_from_list_of_lists(similars))
        remove_included_sets_from_list_of_sets(similarity_sets)
        return remove_duplicates_from_list_of_lists(list_of_sets_to_list_of_lists(similarity_sets)), similarity

    def _find_similar_file_for(self, file, parent_id, potential_matches):
        hash_one = self.database.get_ssdeep_hash(file)
        if hash_one:
            id1 = '{}:{}'.format(parent_id, file)
            for potential_match in potential_matches.files_included:
                id2 = '{}:{}'.format(potential_matches.uid, potential_match)
                hash_two = self.database.get_ssdeep_hash(potential_match)

                if hash_two and get_ssdeep_comparison(hash_one, hash_two) > self.ssdeep_ignore_threshold:
                    yield [id1, id2], get_ssdeep_comparison(hash_one, hash_two)

    @staticmethod
    def produce_similarity_sets(list_of_lists):
        list_of_sets = list_of_lists_to_list_of_sets(list_of_lists)
        for pair_of_sets in make_pairs_of_sets(list_of_sets):
            if check_similarity_of_sets(pair_of_sets, list_of_sets):
                new = collapse_pair_of_sets(pair_of_sets)
                list_of_sets.append(new)
        return list_of_sets

    def beautify_similar_files(self, similar_files, fo_list, similarity):
        result_dict = {}
        for match in similar_files:
            match_dict = self._get_empty_match_dict(fo_list)
            for file in match:
                firm, sub = file.split(':')
                match_dict[firm] = sub
            if convert_uid_list_to_compare_id(match) in similarity.keys():
                match_dict['similarity'] = similarity[convert_uid_list_to_compare_id(match)]
            else:
                match_dict['similarity'] = ''
            result_dict[self._match_id(match)] = match_dict
        return result_dict

    @staticmethod
    def _match_id(match):
        _id = ''
        for file in match:
            firm, sub = file.split(':')
            _id += '{}{}'.format(firm[0:2], sub[0:2])
        return _id

    @staticmethod
    def _get_empty_match_dict(fo_list):
        empty = {}
        for fo in fo_list:
            empty[fo.uid] = None
        return empty

    def _get_non_zero_common_files(self, files_in_all, not_in_all):
        non_zero_files = dict()
        if files_in_all['all']:
            self._evaluate_entropy_for_list_of_uids(files_in_all['all'], non_zero_files, 'all')

        if not_in_all:
            for firmware_uid in not_in_all.keys():
                self._evaluate_entropy_for_list_of_uids(not_in_all[firmware_uid], non_zero_files, firmware_uid)

        return non_zero_files

    def _evaluate_entropy_for_list_of_uids(self, list_of_uids, new_result, firmware_uid):
        non_zero_file_ids = list()
        for uid in list_of_uids:
            if self.database.get_entropy(uid) > 0.1:
                non_zero_file_ids.append(uid)
        if non_zero_file_ids:
            new_result[firmware_uid] = non_zero_file_ids
