import pytest

from test.common_helper import TEST_FW, TEST_GRAPH_DATA_ONE, TEST_GRAPH_DATA_TWO, TEST_GRAPH_DATA_THREE
from web_interface.components.dependency_graph import create_data_graph_edges, create_data_graph_nodes_and_groups


GRAPH_PART = {'nodes':
              [{'label': '/lib/file_one.so', 'entity': '1234567', 'id': '|testgraph|/lib/file_one.so', 'group': 'application/x-executable',
                'full_file_type': 'test text'},
               {'label': '/bin/file_two', 'entity': '7654321', 'id': '|testgraph|/bin/file_two', 'group': 'application/x-executable',
                'full_file_type': 'test text'}],
              'edges': [],
              'groups': ['application/x-executable']}
GRAPH_RES = {'nodes':
             [{'label': '/lib/file_one.so', 'entity': '1234567', 'id': '|testgraph|/lib/file_one.so', 'group': 'application/x-executable',
               'full_file_type': 'test text'},
              {'label': '/bin/file_two', 'entity': '7654321', 'id': '|testgraph|/bin/file_two', 'group': 'application/x-executable',
               'full_file_type': 'test text'}],
             'edges': [{'from': '|testgraph|/bin/file_two', 'to': '|testgraph|/lib/file_one.so', 'id': 0}],
             'groups': ['application/x-executable']}

GRAPH_PART_SYMLINK = {'nodes':
                      [{'label': '/lib/file_one.so', 'entity': '1234567', 'id': '|testgraph|/lib/file_one.so', 'group': 'application/x-executable',
                        'full_file_type': 'test text'},
                       {'label': '/bin/file_two', 'entity': '7654321', 'id': '|testgraph|/bin/file_two', 'group': 'application/x-executable',
                        'full_file_type': 'test text'},
                       {'label': '/sbin/file_three', 'entity': '0987654', 'id': '|testgraph|/sbin/file_three','group': 'inode/symlink',
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
                     'edges': [{'from': '0987654', 'to': '7654321', 'id': 0},
                               {'from': '7654321', 'to': '1234567', 'id': 1}],
                     'groups': ['application/x-executable', 'inode/symlink']}

WHITELIST = ['application/x-executable', 'application/x-sharedlib', 'inode/symlink']


@pytest.mark.parametrize('list_of_objects, parent_uid, root_uid, whitelist, expected_result', [
    ([TEST_GRAPH_DATA_ONE, TEST_GRAPH_DATA_TWO], 'testgraph', TEST_FW.uid, WHITELIST, GRAPH_PART),
    ([TEST_GRAPH_DATA_ONE, TEST_GRAPH_DATA_TWO, TEST_GRAPH_DATA_THREE], 'testgraph', TEST_FW.uid, WHITELIST, GRAPH_PART_SYMLINK),
])
def test_create_graph_nodes_and_groups(list_of_objects, parent_uid, root_uid, whitelist, expected_result):
    assert create_data_graph_nodes_and_groups(list_of_objects, parent_uid, root_uid, whitelist) == expected_result


@pytest.mark.parametrize('list_of_objects, graph_part, expected_graph, expected_missing_analysis', [
    ([TEST_GRAPH_DATA_ONE, TEST_GRAPH_DATA_TWO], GRAPH_PART, GRAPH_RES, 1),
    #([TEST_GRAPH_DATA_ONE, TEST_GRAPH_DATA_TWO, TEST_GRAPH_DATA_THREE], GRAPH_PART_SYMLINK, GRAPH_RES_SYMLINK, 2),
])
def test_create_graph_edges(list_of_objects, graph_part, expected_graph, expected_missing_analysis):
    assert create_data_graph_edges(list_of_objects, graph_part) == (expected_graph, expected_missing_analysis)
