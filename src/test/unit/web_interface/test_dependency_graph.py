import pytest

from web_interface.components.dependency_graph import (
    DepGraphData,
    create_data_graph_edges,
    create_data_graph_nodes_and_groups,
)

entry_1 = DepGraphData(
    '1234567',
    'file_one.so',
    ['/lib/file_one.so'],
    'application/x-executable',
    'test text',
    None,
)
entry_2 = DepGraphData(
    '7654321',
    'file_two',
    ['/bin/file_two'],
    'application/x-executable',
    'test text',
    ['file_one.so'],
)
entry_3 = DepGraphData(
    '0987654',
    'file three',
    ['/sbin/file_three'],
    'inode/symlink',
    'symbolic link to \'../bin/file_two\'',
)

FILE_THREE_RESULT = {
    'label': '/sbin/file_three',
    'elf_analysis_missing': True,
    'entity': '0987654',
    'id': '/sbin/file_three',
    'group': 'inode/symlink',
    'full_file_type': 'symbolic link to \'../bin/file_two\'',
    'linked_libraries': [],
}
FILE_TWO_RESULT = {
    'label': '/bin/file_two',
    'elf_analysis_missing': False,
    'entity': '7654321',
    'id': '/bin/file_two',
    'group': 'application/x-executable',
    'full_file_type': 'test text',
    'linked_libraries': ['file_one.so'],
}
FILE_ONE_RESULT = {
    'label': '/lib/file_one.so',
    'elf_analysis_missing': True,
    'entity': '1234567',
    'id': '/lib/file_one.so',
    'group': 'application/x-executable',
    'full_file_type': 'test text',
    'linked_libraries': [],
}

GRAPH_PART = {'nodes': [FILE_ONE_RESULT, FILE_TWO_RESULT], 'edges': [], 'groups': ['application/x-executable']}
GRAPH_RES = {
    'nodes': [FILE_ONE_RESULT, FILE_TWO_RESULT],
    'edges': [{'from': '/bin/file_two', 'to': '/lib/file_one.so', 'id': 0}],
    'groups': ['application/x-executable'],
}
GRAPH_PART_SYMLINK = {
    'nodes': [FILE_ONE_RESULT, FILE_TWO_RESULT, FILE_THREE_RESULT],
    'edges': [],
    'groups': ['application/x-executable', 'inode/symlink'],
}
GRAPH_RES_SYMLINK = {
    'nodes': [FILE_ONE_RESULT, FILE_TWO_RESULT, FILE_THREE_RESULT],
    'edges': [
        {'from': '/sbin/file_three', 'to': '/bin/file_two', 'id': 0},
        {'from': '/bin/file_two', 'to': '/lib/file_one.so', 'id': 1},
    ],
    'groups': ['application/x-executable', 'inode/symlink'],
}
WHITELIST = ['application/x-executable', 'application/x-sharedlib', 'inode/symlink']


@pytest.mark.parametrize(
    'list_of_objects, expected_result',
    [
        ([entry_1, entry_2], GRAPH_PART),
        ([entry_1, entry_2, entry_3], GRAPH_PART_SYMLINK),
    ],
)
def test_create_graph_nodes_and_groups(list_of_objects, expected_result):
    assert create_data_graph_nodes_and_groups(list_of_objects, WHITELIST) == expected_result


@pytest.mark.parametrize(
    'graph_part, expected_graph, expected_missing_analysis',
    [
        (GRAPH_PART, GRAPH_RES, 1),
        (GRAPH_PART_SYMLINK, GRAPH_RES_SYMLINK, 2),
    ],
)
def test_create_graph_edges(
    graph_part, expected_graph, expected_missing_analysis
):  # pylint: disable=too-many-function-args
    assert create_data_graph_edges(graph_part) == (expected_graph, expected_missing_analysis)
