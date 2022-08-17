from collections import defaultdict
from typing import Dict, List

LEAF_MARKER = '<leaf>'
LEAF_CONSTRAINT = ((LEAF_MARKER, []), )
INDENT = '  '


def visualize_complete_tree(list_of_dot_separated_strings: List[str]) -> Dict[str, str]:
    ''' Visualize the structure of the database entries for the advanced search '''
    new_structure = dict()
    structure = _create_tree_structure(list_of_dot_separated_strings)
    for key in structure:
        if key != LEAF_MARKER:
            new_structure[key] = _visualize_sub_tree(list_of_dot_separated_strings, key)
        else:
            new_structure[key] = structure[key]

    return _convert_multilines_to_single_string(new_structure)


def _visualize_sub_tree(list_of_dot_separated_strings: List[str], analysis_plugin: str) -> List[str]:
    subset = list(string for string in list_of_dot_separated_strings if string.startswith(f'{analysis_plugin}.'))
    return _visualize_tree_structure_as_strings(_create_tree_structure(subset))


def _create_tree_structure(list_of_dot_separated_strings: List[str]) -> defaultdict:
    structure_tree = defaultdict(dict, LEAF_CONSTRAINT)
    for line in list_of_dot_separated_strings:
        _attach_field_to_tree(line, structure_tree)

    _remove_obsolete_leaves(dict(structure_tree))

    return structure_tree


def _attach_field_to_tree(field: str, subtree: defaultdict):
    split_field = field.split('.', 1)
    if len(split_field) == 1:
        new_parts = list(subtree[LEAF_MARKER])
        new_parts.extend(split_field)
        subtree[LEAF_MARKER] = list(set(new_parts))
    else:
        node, remainder = split_field
        if node not in subtree:
            subtree[node] = defaultdict(dict, LEAF_CONSTRAINT)
        _attach_field_to_tree(remainder, subtree[node])


def _visualize_tree_structure_as_strings(level_of_tree: defaultdict, number_of_level: int = 0) -> List[str]:  # pylint: disable=invalid-name
    tree_structure = list()

    for treenode, forks in level_of_tree.items():
        if treenode == LEAF_MARKER:
            for fieldname in forks:
                tree_structure.append(_indent_line(fieldname, number_of_level))
        else:
            tree_structure.append(_indent_line(treenode, number_of_level))
            if isinstance(forks, dict):
                tree_structure.extend(_visualize_tree_structure_as_strings(forks, number_of_level + 1))

    return tree_structure


def _remove_obsolete_leaves(input_dict):
    if not isinstance(input_dict, dict):
        return
    if input_dict[LEAF_MARKER]:
        bottom_leaves = input_dict[LEAF_MARKER]
        for leaf in bottom_leaves:
            if leaf in input_dict:
                input_dict[LEAF_MARKER].remove(leaf)
    for subtree in input_dict.keys():
        _remove_obsolete_leaves(input_dict[subtree])


def _indent_line(line: str, level: int) -> str:
    return f'{INDENT * level}{line}'


def _convert_multilines_to_single_string(dictionary_of_lists: Dict[str, List[str]]) -> Dict[str, str]:  # pylint: disable=invalid-name
    str_dict = {}
    for key, items in dictionary_of_lists.items():
        if not key == LEAF_MARKER:
            str_dict[key] = '\n'.join(items)
        else:
            for root_node in dictionary_of_lists[key]:
                str_dict[root_node] = root_node

    str_dict['complete'] = '\n'.join([str_dict[key] for key in sorted(str_dict)])

    return str_dict
