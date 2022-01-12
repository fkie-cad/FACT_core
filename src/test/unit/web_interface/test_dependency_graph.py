import pytest

from test.common_helper import (  # pylint: disable=wrong-import-order
    TEST_FW, TEST_GRAPH_DATA_ONE, TEST_GRAPH_DATA_THREE, TEST_GRAPH_DATA_TWO
)
from web_interface.components.dependency_graph import create_data_graph_edges, create_data_graph_nodes_and_groups

GRAPH_PART = {'nodes':
              [{'label': '/lib/file_one.so', 'elf_analysis_missing': True, 'entity': '1234567', 'id': '|testgraph|/lib/file_one.so', 'group': 'application/x-executable',
                'full_file_type': 'test text', 'linked_libraries': []},
               {'label': '/bin/file_two', 'elf_analysis_missing': False, 'entity': '7654321', 'id': '|testgraph|/bin/file_two', 'group': 'application/x-executable',
                'full_file_type': 'test text', 'linked_libraries': ['file_one.so']}],
              'edges': [],
              'groups': ['application/x-executable']}
GRAPH_RES = {'nodes':
             [{'label': '/lib/file_one.so', 'elf_analysis_missing': True, 'entity': '1234567', 'id': '|testgraph|/lib/file_one.so', 'group': 'application/x-executable',
               'full_file_type': 'test text', 'linked_libraries': []},
              {'label': '/bin/file_two', 'elf_analysis_missing': False, 'entity': '7654321', 'id': '|testgraph|/bin/file_two', 'group': 'application/x-executable',
               'full_file_type': 'test text', 'linked_libraries': ['file_one.so']}],
             'edges': [{'from': '|testgraph|/bin/file_two', 'to': '|testgraph|/lib/file_one.so', 'id': 0}],
             'groups': ['application/x-executable']}

GRAPH_PART_SYMLINK = {'nodes':
                      [{'label': '/lib/file_one.so', 'elf_analysis_missing': True, 'entity': '1234567', 'id': '|testgraph|/lib/file_one.so', 'group': 'application/x-executable',
                        'full_file_type': 'test text', 'linked_libraries': []},
                       {'label': '/bin/file_two', 'elf_analysis_missing': False, 'entity': '7654321', 'id': '|testgraph|/bin/file_two', 'group': 'application/x-executable',
                        'full_file_type': 'test text', 'linked_libraries': ['file_one.so']},
                       {'label': '/sbin/file_three', 'elf_analysis_missing': True, 'entity': '0987654', 'id': '|testgraph|/sbin/file_three', 'group': 'inode/symlink',
                        'full_file_type': 'symbolic link to \'../bin/file_two\'', 'linked_libraries': []}],
                      'edges': [],
                      'groups': ['application/x-executable', 'inode/symlink']}

GRAPH_RES_SYMLINK = {'nodes':
                     [{'label': '/lib/file_one.so', 'elf_analysis_missing': True, 'entity': '1234567', 'id': '|testgraph|/lib/file_one.so', 'group': 'application/x-executable',
                       'full_file_type': 'test text', 'linked_libraries': []},
                      {'label': '/bin/file_two', 'elf_analysis_missing': False, 'entity': '7654321', 'id': '|testgraph|/bin/file_two', 'group': 'application/x-executable',
                       'full_file_type': 'test text', 'linked_libraries': ['file_one.so']},
                      {'label': '/sbin/file_three', 'elf_analysis_missing': True, 'entity': '0987654', 'id': '|testgraph|/sbin/file_three', 'group': 'inode/symlink',
                       'full_file_type': 'symbolic link to \'../bin/file_two\'', 'linked_libraries': []}],
                     'edges': [{'from': '|testgraph|/sbin/file_three', 'to': '|testgraph|/bin/file_two', 'id': 0},
                               {'from': '|testgraph|/bin/file_two', 'to': '|testgraph|/lib/file_one.so', 'id': 1}],
                     'groups': ['application/x-executable', 'inode/symlink']}

WHITELIST = ['application/x-executable', 'application/x-sharedlib', 'inode/symlink']


@pytest.mark.parametrize('list_of_objects, parent_uid, root_uid, whitelist, expected_result', [
    ([TEST_GRAPH_DATA_ONE, TEST_GRAPH_DATA_TWO], 'testgraph', TEST_FW.uid, WHITELIST, GRAPH_PART),
    ([TEST_GRAPH_DATA_ONE, TEST_GRAPH_DATA_TWO, TEST_GRAPH_DATA_THREE], 'testgraph', TEST_FW.uid, WHITELIST, GRAPH_PART_SYMLINK),
])
def test_create_graph_nodes_and_groups(list_of_objects, parent_uid, root_uid, whitelist, expected_result):
    assert create_data_graph_nodes_and_groups(list_of_objects, parent_uid, root_uid, whitelist) == expected_result


@pytest.mark.parametrize('graph_part, expected_graph, expected_missing_analysis', [
    (GRAPH_PART, GRAPH_RES, 1),
    (GRAPH_PART_SYMLINK, GRAPH_RES_SYMLINK, 2),
])
def test_create_graph_edges(graph_part, expected_graph, expected_missing_analysis):  # pylint: disable=too-many-function-args
    assert create_data_graph_edges(graph_part) == (expected_graph, expected_missing_analysis)
