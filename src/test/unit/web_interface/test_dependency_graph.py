import pytest

from web_interface.components.dependency_graph import (
    DepGraphData, create_data_graph_edges, create_data_graph_nodes_and_groups
)

entry_1 = DepGraphData('1234567', 'file one', 'application/x-executable', 'test text')
entry_2 = DepGraphData('7654321', 'file two', 'application/x-executable', 'test text', ['file one'])
entry_3 = DepGraphData('0987654', 'file three', 'inode/symlink', 'symbolic link to \'file two\'')

GRAPH_PART = {
    'nodes': [
        {'label': 'file one', 'id': '1234567', 'group': 'application/x-executable', 'full_file_type': 'test text'},
        {'label': 'file two', 'id': '7654321', 'group': 'application/x-executable', 'full_file_type': 'test text'}
    ],
    'edges': [],
    'groups': ['application/x-executable']
}
GRAPH_RES = {
    'nodes': [
        {'label': 'file one', 'id': '1234567', 'group': 'application/x-executable', 'full_file_type': 'test text'},
        {'label': 'file two', 'id': '7654321', 'group': 'application/x-executable', 'full_file_type': 'test text'}
    ],
    'edges': [{'from': '7654321', 'to': '1234567', 'id': 0}],
    'groups': ['application/x-executable']
}

GRAPH_PART_SYMLINK = {
    'nodes': [
        {'label': 'file one', 'id': '1234567', 'group': 'application/x-executable', 'full_file_type': 'test text'},
        {'label': 'file two', 'id': '7654321', 'group': 'application/x-executable', 'full_file_type': 'test text'},
        {'label': 'file three', 'id': '0987654', 'group': 'inode/symlink', 'full_file_type': 'symbolic link to \'file two\''}
    ],
    'edges': [],
    'groups': ['application/x-executable', 'inode/symlink']
}

GRAPH_RES_SYMLINK = {
    'nodes': [
        {'label': 'file one', 'id': '1234567', 'group': 'application/x-executable', 'full_file_type': 'test text'},
        {'label': 'file two', 'id': '7654321', 'group': 'application/x-executable', 'full_file_type': 'test text'},
        {'label': 'file three', 'id': '0987654', 'group': 'inode/symlink', 'full_file_type': 'symbolic link to \'file two\''}
    ],
    'edges': [{'from': '0987654', 'to': '7654321', 'id': 0}, {'from': '7654321', 'to': '1234567', 'id': 1}],
    'groups': ['application/x-executable', 'inode/symlink']
}

WHITELIST = ['application/x-executable', 'application/x-sharedlib', 'inode/symlink']


@pytest.mark.parametrize('list_of_objects, whitelist, expected_result', [
    ([entry_1, entry_2], WHITELIST, GRAPH_PART),
    ([entry_1, entry_2, entry_3], WHITELIST, GRAPH_PART_SYMLINK),
])
def test_create_graph_nodes_and_groups(list_of_objects, whitelist, expected_result):
    assert create_data_graph_nodes_and_groups(list_of_objects, whitelist) == expected_result


@pytest.mark.parametrize('list_of_objects, graph_part, expected_graph, expected_missing_analysis', [
    ([entry_1, entry_2], GRAPH_PART, GRAPH_RES, 1),
    ([entry_1, entry_2, entry_3], GRAPH_PART_SYMLINK, GRAPH_RES_SYMLINK, 2),
])
def test_create_graph_edges(list_of_objects, graph_part, expected_graph, expected_missing_analysis):
    assert create_data_graph_edges(list_of_objects, graph_part) == (expected_graph, expected_missing_analysis)
