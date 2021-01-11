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
FILE_THREE = {
    'processed_analysis': {
        'file_type': {
            'mime': 'inode/symlink', 'full': 'symbolic link to \'file two\''
        },
    },
    '_id': '0987654',
    'file_name': 'file three'
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

GRAPH_PART_SYMLINK = {'nodes':
                      [{'label': 'file one', 'id': '1234567', 'group': 'application/x-executable',
                        'full_file_type': 'test text'},
                       {'label': 'file two', 'id': '7654321', 'group': 'application/x-executable',
                        'full_file_type': 'test text'},
                       {'label': 'file three', 'id': '0987654', 'group': 'inode/symlink',
                        'full_file_type': 'symbolic link to \'file two\''}],
                      'edges': [],
                      'groups': ['application/x-executable', 'inode/symlink']}

GRAPH_RES_SYMLINK = {'nodes':
                     [{'label': 'file one', 'id': '1234567', 'group': 'application/x-executable',
                       'full_file_type': 'test text'},
                      {'label': 'file two', 'id': '7654321', 'group': 'application/x-executable',
                       'full_file_type': 'test text'},
                      {'label': 'file three', 'id': '0987654', 'group': 'inode/symlink',
                       'full_file_type': 'symbolic link to \'file two\''}],
                     'edges': [{'id': 0, 'source': '0987654', 'target': '7654321'},
                               {'id': 1, 'source': '7654321', 'target': '1234567'}],
                     'groups': ['application/x-executable', 'inode/symlink']}

WHITELIST = ['application/x-executable', 'application/x-sharedlib', 'inode/symlink']


@pytest.mark.parametrize('list_of_objects, whitelist, expected_result', [
    ([FILE_ONE, FILE_TWO], WHITELIST, GRAPH_PART),
    ([FILE_ONE, FILE_TWO, FILE_THREE], WHITELIST, GRAPH_PART_SYMLINK),
])
def test_create_graph_nodes_and_groups(list_of_objects, whitelist, expected_result):
    assert create_data_graph_nodes_and_groups(list_of_objects, whitelist) == expected_result


@pytest.mark.parametrize('list_of_objects, graph_part, expected_graph, expected_missing_analysis', [
    ([FILE_ONE, FILE_TWO], GRAPH_PART, GRAPH_RES, 1),
    ([FILE_ONE, FILE_TWO, FILE_THREE], GRAPH_PART_SYMLINK, GRAPH_RES_SYMLINK, 2),
])
def test_create_graph_edges(list_of_objects, graph_part, expected_graph, expected_missing_analysis):
    assert create_data_graph_edges(list_of_objects, graph_part) == (expected_graph, expected_missing_analysis)
