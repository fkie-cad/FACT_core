import pytest

from web_interface.components.dependency_graph import create_data_graph_edges, create_data_graph_nodes_and_groups

FILE_ONE = {
    'processed_analysis': {
        'file_type': {
            'mime': 'application/x-executable', 'full': 'test text'
        }
    },
    '_id': '1234567',
    'file_name': 'file one'
}
FILE_TWO = {
    'processed_analysis': {
        'file_type': {
            'mime': 'application/x-executable', 'full': 'test text'
        },
        'elf_analysis': {
            'Output': {
                'libraries': ['file one']
            }
        }
    },
    '_id': '7654321',
    'file_name': 'file two'
}

GRAPH_PART = {'nodes':
              [{'label': 'file one', 'id': '1234567', 'group': 'application/x-executable',
                'full_file_type': 'test text'},
               {'label': 'file two', 'id': '7654321', 'group': 'application/x-executable',
                'full_file_type': 'test text'}],
              'edges': [],
              'groups': ['application/x-executable']}
GRAPH_RES = {'nodes':
             [{'label': 'file one', 'id': '1234567', 'group': 'application/x-executable',
               'full_file_type': 'test text'},
              {'label': 'file two', 'id': '7654321', 'group': 'application/x-executable',
               'full_file_type': 'test text'}],
             'edges': [{'source': '7654321', 'target': '1234567', 'id': 0}],
             'groups': ['application/x-executable']}

WHITELIST = ['application/x-executable', 'application/x-sharedlib', 'inode/symlink']


@pytest.mark.parametrize('list_of_objects, whitelist, expected_result', [
    ([FILE_ONE, FILE_TWO], WHITELIST, GRAPH_PART),
])
def test_create_graph_nodes_and_groups(list_of_objects, whitelist, expected_result):
    assert create_data_graph_nodes_and_groups(list_of_objects, whitelist) == expected_result


@pytest.mark.parametrize('list_of_objects, graph_part, expected_result', [
    ([FILE_ONE, FILE_TWO], GRAPH_PART, GRAPH_RES),
])
def test_create_graph_edges(list_of_objects, graph_part, expected_result):
    assert create_data_graph_edges(list_of_objects, graph_part) == expected_result
