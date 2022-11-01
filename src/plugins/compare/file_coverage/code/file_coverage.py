from itertools import combinations
from typing import Dict, List, Set, Tuple

import networkx
import ssdeep

from compare.PluginBase import CompareBasePlugin
from config import cfg
from helperFunctions.compare_sets import iter_element_and_rest, remove_duplicates_from_list
from helperFunctions.data_conversion import convert_uid_list_to_compare_id
from objects.file import FileObject


class ComparePlugin(CompareBasePlugin):
    '''
    Compares file coverage
    '''

    NAME = 'File_Coverage'
    DEPENDENCIES = []
    FILE = __file__

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ssdeep_ignore_threshold = cfg.expert_settings.ssdeep_ignore

    def compare_function(self, fo_list):
        compare_result = {
            'files_in_common': self._get_intersection_of_files(fo_list),
            'exclusive_files': self._get_exclusive_files(fo_list),
        }

        self._handle_partially_common_files(compare_result, fo_list)

        for result in compare_result.values():
            if isinstance(result, dict):
                result['collapse'] = False

        similar_files, similarity = self._get_similar_files(fo_list, compare_result['exclusive_files'])
        compare_result['similar_files'] = self.combine_similarity_results(similar_files, fo_list, similarity)

        return compare_result

    def _get_exclusive_files(self, fo_list: List[FileObject]) -> Dict[str, List[str]]:
        result = {}
        for current_element, other_elements in iter_element_and_rest(fo_list):
            exclusive_files = set.difference(
                set(current_element.list_of_all_included_files), *self._get_included_file_sets(other_elements)
            )
            result[current_element.uid] = list(exclusive_files)
        return result

    def _get_intersection_of_files(self, fo_list: List[FileObject]) -> Dict[str, List[str]]:
        intersection_of_files = set.intersection(*self._get_included_file_sets(fo_list))
        return {'all': list(intersection_of_files)}

    @staticmethod
    def _get_included_file_sets(fo_list: List[FileObject]) -> List[Set[str]]:
        return [set(file_object.list_of_all_included_files) for file_object in fo_list]

    def _handle_partially_common_files(self, compare_result, fo_list):
        if len(fo_list) > 2:
            compare_result['files_in_more_than_one_but_not_in_all'] = self._get_files_in_more_than_one_but_not_in_all(
                fo_list, compare_result
            )
            not_in_all = compare_result['files_in_more_than_one_but_not_in_all']
        else:
            not_in_all = {}
        compare_result['non_zero_files_in_common'] = self._get_non_zero_common_files(
            compare_result['files_in_common'], not_in_all
        )

    @staticmethod
    def _get_files_in_more_than_one_but_not_in_all(fo_list, result_dict):
        result = {}
        for current_element in fo_list:
            result[current_element.uid] = list(
                set.difference(
                    set(current_element.list_of_all_included_files),
                    result_dict['files_in_common']['all'],
                    result_dict['exclusive_files'][current_element.uid],
                )
            )
        return result

    # ---- SSDEEP similarity ---- #

    def _get_similar_files(
        self, fo_list: List[FileObject], exclusive_files: Dict[str, List[str]]
    ) -> Tuple[List[list], dict]:
        similar_files = []
        similarity = {}
        for parent_one, parent_two in combinations(fo_list, 2):
            for file_one in exclusive_files[parent_one.uid]:
                for similar_file_pair, value in self._find_similar_file_for(file_one, parent_one.uid, parent_two):
                    similar_files.append(similar_file_pair)
                    similarity[convert_uid_list_to_compare_id(similar_file_pair)] = value
        similarity_sets = generate_similarity_sets(remove_duplicates_from_list(similar_files))
        return similarity_sets, similarity

    def _find_similar_file_for(self, file_uid: str, parent_uid: str, comparison_fo: FileObject):
        hash_one = self.database.get_ssdeep_hash(file_uid)
        if hash_one:
            id1 = self._get_similar_file_id(file_uid, parent_uid)
            for potential_match in comparison_fo.files_included:
                id2 = self._get_similar_file_id(potential_match, comparison_fo.uid)
                hash_two = self.database.get_ssdeep_hash(potential_match)
                ssdeep_similarity = ssdeep.compare(hash_one, hash_two)
                if hash_two and ssdeep_similarity > self.ssdeep_ignore_threshold:
                    yield (id1, id2), ssdeep_similarity

    def combine_similarity_results(self, similar_files: List[List[str]], fo_list: List[FileObject], similarity: dict):
        result_dict = {}
        for group_of_similar_files in similar_files:
            match_dict = {fo.uid: None for fo in fo_list}
            for similar_file_id in group_of_similar_files:
                parent_id, file_id = similar_file_id.split(':')
                match_dict[parent_id] = file_id
            match_dict['similarity'] = self._get_similarity_value(group_of_similar_files, similarity)
            result_dict[self._get_similar_file_group_id(group_of_similar_files)] = match_dict
        return result_dict

    @staticmethod
    def _get_similarity_value(group_of_similar_files: List[str], similarity_dict: Dict[str, str]) -> str:
        similarities_list = []
        for id_tuple in combinations(group_of_similar_files, 2):
            similar_file_pair_id = convert_uid_list_to_compare_id(id_tuple)
            if similar_file_pair_id in similarity_dict:
                similarities_list.append(similarity_dict[similar_file_pair_id])
        if not similarities_list:
            return ''
        if len(similarities_list) == 1:
            return similarities_list.pop()
        similarities_list = [int(v) for v in similarities_list]
        return f'{min(similarities_list)} ‒ {max(similarities_list)}'

    @staticmethod
    def _get_similar_file_id(file_uid: str, parent_uid: str) -> str:
        return f'{parent_uid}:{file_uid}'

    @staticmethod
    def _get_similar_file_group_id(similar_file_group: List[str]) -> str:
        group_id = ''
        for similar_file_id in similar_file_group:
            parent_uid, file_uid = similar_file_id.split(':')
            group_id = f'{group_id}{parent_uid[:4]}{file_uid[:4]}'
        return group_id

    def _get_non_zero_common_files(self, files_in_all, not_in_all):
        non_zero_files = {}
        if files_in_all['all']:
            self._evaluate_entropy_for_list_of_uids(files_in_all['all'], non_zero_files, 'all')

        if not_in_all:
            for firmware_uid in not_in_all.keys():
                self._evaluate_entropy_for_list_of_uids(not_in_all[firmware_uid], non_zero_files, firmware_uid)

        return non_zero_files

    def _evaluate_entropy_for_list_of_uids(self, list_of_uids, new_result, firmware_uid):
        non_zero_file_ids = []
        for uid in list_of_uids:
            if self.database.get_entropy(uid) > 0.1:
                non_zero_file_ids.append(uid)
        if non_zero_file_ids:
            new_result[firmware_uid] = non_zero_file_ids


def generate_similarity_sets(list_of_pairs: List[Tuple[str, str]]) -> List[List[str]]:
    graph = networkx.Graph()
    for file1, file2 in list_of_pairs:
        graph.add_edge(file1, file2)
    return [sorted(c) for c in networkx.algorithms.clique.find_cliques(graph)]
