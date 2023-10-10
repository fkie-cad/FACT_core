from __future__ import annotations

from itertools import combinations

import networkx
import ssdeep

import config
from compare.PluginBase import CompareBasePlugin
from helperFunctions.compare_sets import iter_element_and_rest, remove_duplicates_from_list
from helperFunctions.data_conversion import convert_uid_list_to_compare_id
from objects.firmware import Firmware
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from helperFunctions.virtual_file_path import VFP
    from helperFunctions.types import UID
    from objects.file import FileObject


class ComparePlugin(CompareBasePlugin):
    """
    Compares file coverage
    """

    NAME = 'File_Coverage'
    DEPENDENCIES = []  # noqa: RUF012
    FILE = __file__

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ssdeep_ignore_threshold = config.backend.ssdeep_ignore

    def compare_function(self, fo_list: list[FileObject]):
        if any(fo.list_of_all_included_files is None for fo in fo_list):
            # list_of_all_included_files should be set for all FOs by the compare module
            # for the rest of this plugin, we assume that list_of_all_included_files is always set
            uids = {fo.uid for fo in fo_list}
            raise RuntimeError(f'Cannot run file_coverage plugin: list_of_all_included_files is missing from FO {uids}')

        compare_result: dict[str, dict[str, Any]] = {
            'files_in_common': self._get_intersection_of_files(fo_list),
            'exclusive_files': self._get_exclusive_files(fo_list),
        }

        self._handle_partially_common_files(compare_result, fo_list)

        for result in compare_result.values():
            if isinstance(result, dict):
                result['collapse'] = False

        similar_files, similarity = self._get_similar_files(fo_list, compare_result['exclusive_files'])
        compare_result['similar_files'] = self.combine_similarity_results(similar_files, fo_list, similarity)

        if len(fo_list) == 2 and all(isinstance(fo, Firmware) for fo in fo_list):  # noqa: PLR2004
            compare_result['changed_text_files'] = self._find_changed_text_files(
                fo_list, compare_result['files_in_common']['all']
            )

        return compare_result

    def _get_exclusive_files(self, fo_list: list[FileObject]) -> dict[str, list[UID]]:
        result = {}
        for current_element, other_elements in iter_element_and_rest(fo_list):
            exclusive_files = set.difference(
                set(current_element.list_of_all_included_files),  # type: ignore[arg-type]
                *self._get_included_file_sets(other_elements),
            )
            result[current_element.uid] = list(exclusive_files)
        return result

    def _get_intersection_of_files(self, fo_list: list[FileObject]) -> dict[str, list[UID]]:
        intersection_of_files = set.intersection(*self._get_included_file_sets(fo_list))
        return {'all': list(intersection_of_files)}

    @staticmethod
    def _get_included_file_sets(fo_list: Iterable[FileObject]) -> list[set[str]]:
        return [set(file_object.list_of_all_included_files) for file_object in fo_list]  # type: ignore[arg-type]

    def _handle_partially_common_files(self, compare_result: dict[str, dict], fo_list: list[FileObject]):
        if len(fo_list) > 2:  # noqa: PLR2004
            compare_result['files_in_more_than_one_but_not_in_all'] = self._get_files_in_more_than_one_but_not_in_all(
                fo_list, compare_result
            )
            not_in_all: dict[UID, list[UID]] = compare_result['files_in_more_than_one_but_not_in_all']
        else:
            not_in_all = {}
        compare_result['non_zero_files_in_common'] = self._get_non_zero_common_files(
            compare_result['files_in_common'], not_in_all
        )

    @staticmethod
    def _get_files_in_more_than_one_but_not_in_all(
        fo_list: list[FileObject], result_dict: dict[str, dict]
    ) -> dict[UID, list[UID]]:
        result = {}
        for current_element in fo_list:
            assert current_element.list_of_all_included_files is not None, 'file list should be set in compare module'
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
        self, fo_list: list[FileObject], exclusive_files: dict[str, list[str]]
    ) -> tuple[list[list], dict]:
        similar_files = []
        similarity = {}
        for parent_one, parent_two in combinations(fo_list, 2):
            for file_one in exclusive_files[parent_one.uid]:
                for similar_file_pair, value in self._find_similar_file_for(file_one, parent_one.uid, parent_two):
                    similar_files.append(similar_file_pair)
                    similarity[convert_uid_list_to_compare_id(similar_file_pair)] = value
        similarity_sets = generate_similarity_sets(remove_duplicates_from_list(similar_files))
        return similarity_sets, similarity

    def _find_similar_file_for(self, file_uid: UID, parent_uid: UID, comparison_fo: FileObject):
        hash_one = self.database.get_ssdeep_hash(file_uid)
        if hash_one:
            id1 = self._get_similar_file_id(file_uid, parent_uid)
            for potential_match in comparison_fo.files_included:
                id2 = self._get_similar_file_id(potential_match, comparison_fo.uid)
                hash_two = self.database.get_ssdeep_hash(potential_match)
                ssdeep_similarity = ssdeep.compare(hash_one, hash_two)
                if hash_two and ssdeep_similarity > self.ssdeep_ignore_threshold:
                    yield (id1, id2), ssdeep_similarity

    def combine_similarity_results(self, similar_files: list[list[str]], fo_list: list[FileObject], similarity: dict):
        result_dict = {}
        for group_of_similar_files in similar_files:
            match_dict: dict[UID, UID | None] = {fo.uid: None for fo in fo_list}
            for similar_file_id in group_of_similar_files:
                parent_id, file_id = similar_file_id.split(':')
                match_dict[parent_id] = file_id
            match_dict['similarity'] = self._get_similarity_value(group_of_similar_files, similarity)
            result_dict[self._get_similar_file_group_id(group_of_similar_files)] = match_dict
        return result_dict

    @staticmethod
    def _get_similarity_value(group_of_similar_files: list[str], similarity_dict: dict[str, str]) -> str:
        similarities_list = []
        for id_tuple in combinations(group_of_similar_files, 2):
            similar_file_pair_id = convert_uid_list_to_compare_id(id_tuple)
            if similar_file_pair_id in similarity_dict:
                similarities_list.append(similarity_dict[similar_file_pair_id])
        if not similarities_list:
            return ''
        if len(similarities_list) == 1:
            return similarities_list.pop()
        similarity_values = [int(v) for v in similarities_list]
        return f'{min(similarity_values)} ‒ {max(similarity_values)}'

    @staticmethod
    def _get_similar_file_id(file_uid: str, parent_uid: str) -> str:
        return f'{parent_uid}:{file_uid}'

    @staticmethod
    def _get_similar_file_group_id(similar_file_group: list[str]) -> str:
        group_id = ''
        for similar_file_id in similar_file_group:
            parent_uid, file_uid = similar_file_id.split(':')
            group_id = f'{group_id}{parent_uid[:4]}{file_uid[:4]}'
        return group_id

    def _get_non_zero_common_files(
        self, files_in_all: dict[str, list[UID]], not_in_all: dict[UID, list[UID]]
    ) -> dict[str, list[UID]]:
        non_zero_files = {}
        if files_in_all['all']:
            non_zero_files.update(self._evaluate_entropy_for_list_of_uids(files_in_all['all'], 'all'))

        if not_in_all:
            for firmware_uid in not_in_all:
                non_zero_files.update(self._evaluate_entropy_for_list_of_uids(not_in_all[firmware_uid], firmware_uid))

        return non_zero_files

    def _evaluate_entropy_for_list_of_uids(self, list_of_uids: list[UID], firmware_uid: str) -> dict[str, list[UID]]:
        result = {}
        non_zero_file_ids = []
        for uid in list_of_uids:
            if self.database.get_entropy(uid) > 0.1:  # noqa: PLR2004
                non_zero_file_ids.append(uid)
        if non_zero_file_ids:
            result[firmware_uid] = non_zero_file_ids
        return result

    def _find_changed_text_files(
        self, fo_list: list[FileObject], common_files: list[str]
    ) -> dict[VFP, list[tuple[UID, UID]]]:
        """
        Find text files that have the same path but different content for the file objects that are compared. The idea
        is to find config files that were changed between different versions of a firmware. Only works if two firmware
        objects are compared (and returns an empty result otherwise).
        :param fo_list: the list of compared file objects
        :param common_files: list of UIDs that are in both file objects
        :return: a dict with paths as keys and a list of UID pairs (tuples) as values
        """
        common_set = set(common_files)
        vfp_a = self.database.get_vfp_of_included_text_files(fo_list[0].uid, blacklist=common_set)
        vfp_b = self.database.get_vfp_of_included_text_files(fo_list[1].uid, blacklist=common_set)

        changed_text_files: dict[VFP, list[tuple[UID, UID]]] = {}
        for common_path in set(vfp_a).intersection(set(vfp_b)):
            # vfp_x[common_path] should usually contain only 1 element (except if there are multiple files with the same
            # path, e.g. if the FW contains multiple file systems, in which case all combinations are added)
            for uid_1 in vfp_a[common_path]:
                for uid_2 in vfp_b[common_path]:
                    changed_text_files.setdefault(common_path, []).append((uid_1, uid_2))
        return changed_text_files


def generate_similarity_sets(list_of_pairs: list[tuple[str, str]]) -> list[list[str]]:
    graph = networkx.Graph()
    for file1, file2 in list_of_pairs:
        graph.add_edge(file1, file2)
    return [sorted(c) for c in networkx.algorithms.clique.find_cliques(graph)]
