from __future__ import annotations

import pytest

from web_interface.file_tree.file_tree import (
    FileTreeData,
    VirtualPathFileTree,
    _root_is_virtual,
    get_icon_for_mime,
    get_mime_for_text_file,
    remove_virtual_path_from_root,
)
from web_interface.file_tree.file_tree_node import FileTreeNode

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
MIME_PATH = '/static/file_icons/mimetypes/'


@pytest.mark.parametrize(
    ('mime_type', 'icon'),
    [
        (None, f'{MIME_PATH}unknown.svg'),
        ('application/zip', f'{MIME_PATH}application-zip.svg'),
        ('filesystem/some_filesystem', '/static/file_icons/filesystem.svg'),
        ('application/x-executable', f'{MIME_PATH}application-x-executable.svg'),
        ('inode/symlink', f'{MIME_PATH}inode-symlink.svg'),
        ('text/html', f'{MIME_PATH}text-html.svg'),
        ('text/foobar', f'{MIME_PATH}text-x-generic.svg'),
        ('firmware/generic', '/static/file_icons/firmware.svg'),
        ('text/plain', f'{MIME_PATH}text-plain.svg'),
        ('image/png', f'{MIME_PATH}image-png.svg'),
        ('image/foobar', f'{MIME_PATH}image-x-generic.svg'),
        ('audio/mpeg', f'{MIME_PATH}audio-mpeg.svg'),
        ('audio/foobar', f'{MIME_PATH}audio-x-generic.svg'),
        ('some unknown mime type', f'{MIME_PATH}unknown.svg'),
    ],
)
def test_get_icon_for_mime(mime_type, icon):
    assert get_icon_for_mime(mime_type) == icon


@pytest.mark.parametrize(
    ('filename', 'mime'),
    [
        ('foo', 'text/plain'),
        ('foo.py', 'text-x-python'),
        ('foo.css', 'text-css'),
        ('README', 'text-x-readme'),
    ],
)
def test_get_mime_for_text_file(filename, mime):
    assert get_mime_for_text_file(filename) == mime


class TestFileTree:
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
    ('input_data', 'expected_output'),
    [
        ([], False),
        ([NON_VIRTUAL_TREE_ROOT], False),
        ([VIRTUAL_TREE_ROOT], True),
    ],
)
def test_root_is_virtual(input_data, expected_output):
    assert _root_is_virtual(input_data) == expected_output


@pytest.mark.parametrize(
    ('input_data', 'expected_output'),
    [
        ([NON_VIRTUAL_TREE_ROOT], [NON_VIRTUAL_TREE_ROOT]),
        ([VIRTUAL_TREE_ROOT], [NON_VIRTUAL_TREE_ROOT]),  # virtual root includes non-virtual root as child
    ],
)
def test_remove_virtual_path_from_root(input_data, expected_output):
    assert remove_virtual_path_from_root(input_data) == expected_output


class TestVirtualPathFileTree:
    tree_data = {  # noqa: RUF012
        'uid': 'uid',
        'file_name': 'foo.exe',
        'size': 1,
        'mime': 'footype',
        'included_files': set(),
        'file_mode_data': {},
    }

    def test_multiple_paths(self):
        fo_data = {**self.tree_data, 'virtual_file_path': {'root_uid': ['/dir1/file1', '/dir2/file2']}}
        nodes = self._nodes_by_name(VirtualPathFileTree('root_uid', 'root_uid', FileTreeData(**fo_data)))
        assert len(nodes) == 2, 'wrong number of nodes created'
        assert 'dir1' in nodes
        assert 'dir2' in nodes
        assert len(nodes['dir1'].children) == 1
        assert nodes['dir1'].get_names_of_children() == ['file1']

    def test_multiple_occurrences(self):
        fo_data = {
            **self.tree_data,
            'virtual_file_path': {'parent_1': ['/foo/bar'], 'parent_2': ['/other/path']},
        }
        nodes = self._nodes_by_name(VirtualPathFileTree('root_uid', 'parent_1', FileTreeData(**fo_data)))
        assert len(nodes) == 1, 'includes duplicates'
        assert 'foo' in nodes
        assert 'other' not in nodes

    @staticmethod
    def _nodes_by_name(file_tree: VirtualPathFileTree) -> dict[str, FileTreeNode]:
        return {node.name: node for node in file_tree.get_file_tree_nodes()}
