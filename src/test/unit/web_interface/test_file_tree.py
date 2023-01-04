from typing import Dict

import pytest

from web_interface.file_tree.file_tree import (
    FileTreeData,
    VirtualPathFileTree,
    _get_partial_virtual_paths,
    _get_vpath_relative_to,
    _root_is_virtual,
    get_icon_for_file,
    remove_virtual_path_from_root,
)
from web_interface.file_tree.file_tree_node import FileTreeNode

# pylint: disable=protected-access

NON_VIRTUAL_TREE_ROOT = {
    'a_attr': {'href': '/analysis/someUID/ro/someUID'},
    'children': True,
    'data': {'uid': 'someUID'},
    'icon': 'pic.png',
    'li_attr': {'href': '/analysis/someUID/ro/someUID'},
    'text': 'abc',
}
VIRTUAL_TREE_ROOT = {
    'a_attr': {'href': '#'},
    'children': [NON_VIRTUAL_TREE_ROOT],
    'icon': 'pic.png',
    'li_attr': {'href': '#'},
    'text': 'misc',
}


@pytest.mark.parametrize(
    'mime_type, filename, icon',
    [
        ('application/zip', '', '/static/file_icons/mime/application-zip.png'),
        ('filesystem/some_filesystem', '', '/static/file_icons/filesystem.png'),
        ('application/x-executable', '', '/static/file_icons/mime/application-x-executable.png'),
        ('inode/symlink', '', '/static/file_icons/mime/inode-symlink.png'),
        ('text/html', '', '/static/file_icons/mime/text-html.png'),
        ('text/foobar', '', '/static/file_icons/mime/txt.png'),
        ('firmware/generic', '', '/static/file_icons/mime/application-x-firmware.png'),
        ('text/plain', '', '/static/file_icons/mime/text-plain.png'),
        ('image/png', '', '/static/file_icons/mime/image-png.png'),
        ('image/foobar', '', '/static/file_icons/mime/jpg.png'),
        ('audio/mpeg', '', '/static/file_icons/mime/audio-mpeg.png'),
        ('audio/foobar', '', '/static/file_icons/mime/audio-x-generic.png'),
        ('some unknown mime type', '', '/static/file_icons/mime/unknown.png'),
        ('some unknown mime type', 'foo.sh', '/static/file_icons/mime/application-x-shellscript.png'),
    ],
)
def test_get_icon_for_file(mime_type, filename, icon):
    assert get_icon_for_file(mime_type, filename) == icon


class TestFileTree:  # pylint: disable=no-self-use
    def test_node_creation(self):
        parent_node = FileTreeNode('123', virtual=False, name='parent', size=1, mime_type='somefile')
        child_node = FileTreeNode('456', root_uid='123', virtual=True, name='child')
        parent_node.add_child_node(child_node)

        assert parent_node.uid == '123'
        assert parent_node.root_uid is None
        assert child_node.root_uid == '123'
        assert not parent_node.virtual
        assert parent_node.size == 1
        assert parent_node.type == 'somefile'
        assert parent_node.has_children
        assert parent_node.get_list_of_child_nodes() == [child_node]
        assert parent_node.get_id() == ('parent', False)
        assert list(parent_node.children.keys()) == [child_node.get_id()]
        assert parent_node.get_names_of_children() == [child_node.name]
        assert not child_node.has_children
        assert child_node in parent_node
        assert 'Node ' in repr(parent_node)
        assert parent_node != child_node
        assert parent_node.print_tree() is None

    def test_node_merging(self):
        parent_node = FileTreeNode('123', virtual=False, name='parent', size=1, mime_type='somefile')
        child_node_folder_1 = FileTreeNode(None, virtual=True, name='folder')
        child_node_folder_2 = FileTreeNode(None, virtual=True, name='folder')
        child_node_file_1 = FileTreeNode('abc', virtual=False, name='file_1')
        child_node_file_2 = FileTreeNode('def', virtual=False, name='file_2')
        child_node_folder_1.add_child_node(child_node_file_1)
        child_node_folder_2.add_child_node(child_node_file_2)
        parent_node.add_child_node(child_node_folder_1)
        parent_node.add_child_node(child_node_folder_2)

        assert parent_node.has_children
        assert len(parent_node.get_list_of_child_nodes()) == 1
        assert list(parent_node.children.keys()) == [child_node_folder_1.get_id()]
        assert child_node_folder_1 in parent_node
        assert child_node_folder_2 in parent_node
        assert len(parent_node.children[child_node_folder_1.get_id()].get_list_of_child_nodes()) == 2
        folder_id = child_node_folder_1.get_id()
        assert child_node_file_1 in parent_node.children[folder_id]
        assert child_node_file_2 in parent_node.children[folder_id]


VIRTUAL_PATH_INPUT = {
    'abc': ['|abc|def|ghi|folder_1/folder_2/file'],
    '123': ['|123|456|ghi|folder_1/folder_2/file'],
    'foo': ['|foo|bar|/dir_a/file_a', '|foo|bar|/dir_a/file_b', '|foo|bar|/dir_a/dir_b/file_c'],
}


@pytest.mark.parametrize(
    'uid, expected_output',
    [
        ('abc', ['|abc|def|ghi|folder_1/folder_2/file']),
        ('ghi', ['|ghi|folder_1/folder_2/file']),
        ('xyz', ['|xyz|']),
        ('456', ['|456|ghi|folder_1/folder_2/file']),
        ('foo', ['|foo|bar|/dir_a/dir_b/file_c', '|foo|bar|/dir_a/file_a', '|foo|bar|/dir_a/file_b']),
        ('bar', ['|bar|/dir_a/dir_b/file_c', '|bar|/dir_a/file_a', '|bar|/dir_a/file_b']),
    ],
)
def test_get_partial_virtual_paths(uid, expected_output):
    assert _get_partial_virtual_paths(VIRTUAL_PATH_INPUT, uid) == expected_output


@pytest.mark.parametrize(
    'virtual_path, uid, expected_output',
    [
        ('|abc|def|ghi|folder_1/folder_2/file', 'abc', '|abc|def|ghi|folder_1/folder_2/file'),
        ('|abc|def|ghi|folder_1/folder_2/file', 'def', '|def|ghi|folder_1/folder_2/file'),
        ('|abc|def|ghi|folder_1/folder_2/file', 'ghi', '|ghi|folder_1/folder_2/file'),
    ],
)
def test_get_vpath_relative_to(virtual_path, uid, expected_output):
    assert _get_vpath_relative_to(virtual_path, uid) == expected_output


@pytest.mark.parametrize(
    'input_data, expected_output',
    [
        ([], False),
        ([NON_VIRTUAL_TREE_ROOT], False),
        ([VIRTUAL_TREE_ROOT], True),
    ],
)
def test_root_is_virtual(input_data, expected_output):
    assert _root_is_virtual(input_data) == expected_output


@pytest.mark.parametrize(
    'input_data, expected_output',
    [
        ([NON_VIRTUAL_TREE_ROOT], [NON_VIRTUAL_TREE_ROOT]),
        ([VIRTUAL_TREE_ROOT], [NON_VIRTUAL_TREE_ROOT]),  # virtual root includes non-virtual root as child
    ],
)
def test_remove_virtual_path_from_root(input_data, expected_output):
    assert remove_virtual_path_from_root(input_data) == expected_output


class TestVirtualPathFileTree:
    tree_data = {'uid': 'uid', 'file_name': 'foo.exe', 'size': 1, 'mime': 'footype', 'included_files': set()}

    def test_multiple_paths(self):
        fo_data = {**self.tree_data, 'virtual_file_path': {'root_uid': ['root_uid|/foo/bar', 'root_uid|/other/path']}}
        nodes = self._nodes_by_name(VirtualPathFileTree('root_uid', 'root_uid', FileTreeData(**fo_data)))
        assert len(nodes) == 2, 'wrong number of nodes created'
        assert 'foo' in nodes and 'other' in nodes
        assert len(nodes['foo'].children) == 1
        assert nodes['foo'].get_names_of_children() == ['bar']

    def test_multiple_occurrences(self):
        fo_data = {
            **self.tree_data,
            'virtual_file_path': {'root_uid': ['root_uid|parent_uid|/foo/bar', 'root_uid|other_uid|/other/path']},
        }
        nodes = self._nodes_by_name(VirtualPathFileTree('root_uid', 'parent_uid', FileTreeData(**fo_data)))
        assert len(nodes) == 1, 'includes duplicates'
        assert 'foo' in nodes and 'other' not in nodes

    def test_fo_root(self):
        fo_data = {**self.tree_data, 'virtual_file_path': {'fw_uid': ['fw_uid|fo_root_uid|parent_uid|/foo/bar']}}
        tree = VirtualPathFileTree('fo_root_uid', 'parent_uid', FileTreeData(**fo_data))
        assert tree.virtual_file_paths[0].startswith('|fo_root_uid'), 'incorrect partial vfp'

    @staticmethod
    def _nodes_by_name(file_tree: VirtualPathFileTree) -> Dict[str, FileTreeNode]:
        return {node.name: node for node in file_tree.get_file_tree_nodes()}
