from collections import defaultdict

LEAF_MARKER = '<leaf>'
LEAF_CONSTRAINT = ((LEAF_MARKER, []),)
INDENT = '  '


def visualize_complete_tree(list_of_dot_separated_strings):
    new_structure = dict()
    structure = _create_tree_structure(list_of_dot_separated_strings)
    for key in structure:
        if key != LEAF_MARKER:
            new_structure[key] = visualize_sub_tree(list_of_dot_separated_strings, key)
        else:
            new_structure[key] = structure[key]

    return _convert_multilines_to_single_string(new_structure)


def visualize_sub_tree(list_of_dot_separated_strings, analysis_plugin):
    subset = list(string for string in list_of_dot_separated_strings if string.startswith("{}.".format(analysis_plugin)))
    return _visualize_tree_structure_as_strings(_create_tree_structure(subset))


def _create_tree_structure(list_of_dot_separated_strings):
    structure_tree = defaultdict(dict, LEAF_CONSTRAINT)
    for line in list_of_dot_separated_strings:
        _attach_field_to_tree(line, structure_tree)

    _remove_obsolete_leafs(dict(structure_tree))

    return structure_tree


def _attach_field_to_tree(field, subtree):
    splitted_field = field.split('.', 1)
    if len(splitted_field) == 1:
        new_parts = list(subtree[LEAF_MARKER])
        new_parts.extend(splitted_field)
        subtree[LEAF_MARKER] = list(set(new_parts))
    else:
        node, remainder = splitted_field
        if node not in subtree:
            subtree[node] = defaultdict(dict, LEAF_CONSTRAINT)
        _attach_field_to_tree(remainder, subtree[node])


def _visualize_tree_structure_as_strings(level_of_tree, number_of_level=0):
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


def _remove_obsolete_leafs(input_dict):
    if not isinstance(input_dict, dict):
        return
    if input_dict[LEAF_MARKER]:
        bottom_leafs = input_dict[LEAF_MARKER]
        for leaf in bottom_leafs:
            if leaf in input_dict:
                input_dict[LEAF_MARKER].remove(leaf)
    for subtree in input_dict.keys():
        _remove_obsolete_leafs(input_dict[subtree])


def _indent_line(line, level):
    return "{}{}".format(INDENT * level, line)


def _convert_multilines_to_single_string(dictionary_of_lists):
    for key, items in list(dictionary_of_lists.items()):
        if not key == LEAF_MARKER:
            dictionary_of_lists[key] = '\n'.join(items)
        else:
            root_nodes = dictionary_of_lists.pop(LEAF_MARKER)
            for root_node in root_nodes:
                dictionary_of_lists[root_node] = root_node

    for key in sorted(dictionary_of_lists.keys()):
        if 'complete' not in dictionary_of_lists:
            dictionary_of_lists['complete'] = ""
        dictionary_of_lists['complete'] += "\n{}".format(dictionary_of_lists[key])
    dictionary_of_lists['complete'] = dictionary_of_lists['complete'].lstrip('\n')

    return dictionary_of_lists
