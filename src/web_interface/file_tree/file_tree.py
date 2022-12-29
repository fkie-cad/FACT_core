from __future__ import annotations

from collections.abc import Iterable
from itertools import chain
from typing import NamedTuple

from web_interface.file_tree.file_tree_node import FileTreeNode

ARCHIVE_FILE_TYPES = [
    'application/gzip',
    'application/java-archive',
    'application/rar',
    'application/vnd.ms-cab-compressed',
    'application/x-7z-compressed',
    'application/x-ace',
    'application/x-adf',
    'application/x-alzip',
    'application/x-arc',
    'application/x-archive',
    'application/x-arj',
    'application/x-bzip2',
    'application/x-cab',
    'application/x-chm',
    'application/x-compress',
    'application/x-cpio',
    'application/x-debian-package',
    'application/x-dms',
    'application/x-gzip',
    'application/x-iso9660-image',
    'application/x-lha',
    'application/x-lrzip',
    'application/x-lzh',
    'application/x-lzip',
    'application/x-lzma',
    'application/x-lzop',
    'application/x-rar',
    'application/x-redhat-package-manager',
    'application/x-rpm',
    'application/x-rzip',
    'application/x-shar',
    'application/x-sit',
    'application/x-sitx',
    'application/x-stuffit',
    'application/x-stuffitx',
    'application/x-tar',
    'application/x-xz',
    'application/x-zip-compressed',
    'application/x-zoo',
    'application/zip',
    'application/zpaq',
    'audio/flac',
    'compression/zlib',
]
TYPE_TO_ICON = {
    'application/x-executable': '/static/file_icons/binary.png',
    'inode/symlink': '/static/file_icons/link.png',
    'text/html': '/static/file_icons/html.png',
}
TYPE_CATEGORY_TO_ICON = {
    'audio/': '/static/file_icons/multimedia.png',
    'filesystem/': '/static/file_icons/filesystem.png',
    'firmware/': '/static/file_icons/firmware.png',
    'image/': '/static/file_icons/image.png',
    'text/': '/static/file_icons/text.png',
}


class FileTreeData(NamedTuple):
    uid: str
    file_name: str
    size: int
    virtual_file_path: dict[str, list[str]]
    mime: str
    included_files: set[str]


def get_correct_icon_for_mime(mime_type: str | None) -> str:
    '''
    Retrieve the path to appropriate icon for a given mime type. The icons are located in the static folder of the
    web interface and the paths therefore start with "/static". Archive types all receive the same icon.

    :param mime_type: The MIME type of a file (in the file tree).
    '''
    if mime_type is None:
        return '/static/file_icons/unknown.png'
    if mime_type in ARCHIVE_FILE_TYPES:
        return '/static/file_icons/archive.png'
    if mime_type in TYPE_TO_ICON:
        return TYPE_TO_ICON[mime_type]
    for mime_category, icon_path in TYPE_CATEGORY_TO_ICON.items():
        if mime_category in mime_type:
            return icon_path
    return '/static/file_icons/unknown.png'


def _get_partial_virtual_paths(virtual_path: dict[str, list[str]], new_root: str) -> list[str]:
    '''
    Returns a list of new partial virtual paths with ``new_root`` as the new root element.
    If no paths containing ``new_root`` are found, a fallback path is created, consisting only of ``new_root``.
    '''
    paths_with_new_root = {
        _get_vpath_relative_to(vpath, new_root) for vpath in chain(*virtual_path.values()) if new_root in vpath
    }
    if not paths_with_new_root:
        return [f'|{new_root}|']
    return sorted(paths_with_new_root)


def _get_vpath_relative_to(virtual_path: str, uid: str):
    vpath_elements = virtual_path.split('|')
    index = vpath_elements.index(uid)
    return '|'.join([''] + vpath_elements[index:])


def _root_is_virtual(root: list[dict]) -> bool:
    try:
        return root[0]['a_attr'] == {'href': '#'}
    except (KeyError, IndexError):
        return False


def remove_virtual_path_from_root(root: list[dict]) -> list[dict]:
    '''
    When a file object is the root, the directories that contain the file object need to be removed so that the file
    tree is displayed correctly in the web interface.
    '''
    while _root_is_virtual(root):
        root = root[0]['children']
    return root


class VirtualPathFileTree:
    '''
    This class represents a layer of the file tree (a partial tree) for a ``Firmware`` or ``FileObject`` as root and
    is based on the virtual file paths of its child objects (unpacked files). "Layer" means that the file tree is
    created in layers as it is unfolded (one partial tree for each file).

    This partial layer tree has a ``Firmware`` or ``FileObject`` as root, directories as inner nodes (the inner elements
    of the virtual file path) and ``FileObject``s as outer nodes ("leaves" of the tree, the end of the virtual file
    path).

    Both ``Firmware`` and ``FileObject`` vertices are represented by ``FileTreeNode`` objects.

    :param root_uid: The uid of the root node of the file tree.
    :param fo_data: The firmware / file object data from the database that is needed to create the file tree.
    :param whitelist: A whitelist of file names needed to display partial trees in comparisons.
    '''

    def __init__(self, root_uid: str, parent_uid: str, fo_data: FileTreeData, whitelist: list[str] | None = None):
        self.uid = fo_data.uid
        self.root_uid = root_uid if root_uid else list(fo_data.virtual_file_path)[0]
        self.parent_uid = parent_uid
        self.fo_data: FileTreeData = fo_data
        self.whitelist = whitelist
        self.virtual_file_paths = self._get_virtual_file_paths()

    def _get_virtual_file_paths(self) -> list[str]:
        if self._file_tree_is_for_file_object():
            return _get_partial_virtual_paths(self.fo_data.virtual_file_path, self.root_uid)
        return self.fo_data.virtual_file_path[self.root_uid]

    def _file_tree_is_for_file_object(self) -> bool:
        return self.root_uid not in self.fo_data.virtual_file_path

    def get_file_tree_nodes(self) -> Iterable[FileTreeNode]:
        '''
        Create ``FileTreeNode`` s for the elements of the root's virtual file path. The same file may occur several
        times with different virtual paths. Returns a sequence of nodes, representing the subsequent layer in the
        file tree (which themselves may contain child nodes).

        :return: An iterable sequence of nodes of the file tree.
        '''
        for virtual_path in self.virtual_file_paths:
            containers, *path_elements = virtual_path.split('/')
            containers = [c for c in containers.split('|') if c]
            if self.parent_uid is None or containers[-1] == self.parent_uid:
                yield self._create_node_from_virtual_path(path_elements)

    def _create_node_from_virtual_path(self, current_virtual_path: list[str]) -> FileTreeNode:
        if len(current_virtual_path) > 1:
            return self._get_node_for_virtual_file(current_virtual_path)
        return self._get_node_for_real_file(current_virtual_path)

    def _get_node_for_virtual_file(self, current_virtual_path: list[str]) -> FileTreeNode:
        current_element, *rest_of_virtual_path = current_virtual_path
        node = FileTreeNode(uid=None, root_uid=self.root_uid, virtual=True, name=current_element)
        node.add_child_node(self._create_node_from_virtual_path(rest_of_virtual_path))
        return node

    def _get_node_for_real_file(self, current_virtual_path: list[str]) -> FileTreeNode:
        return FileTreeNode(
            self.uid,
            self.root_uid,
            virtual=False,
            name=self._get_file_name(current_virtual_path),
            size=self.fo_data.size,
            mime_type=self.fo_data.mime,
            has_children=self._has_children(),
        )

    def _get_file_name(self, current_virtual_path: list[str]) -> str:
        return current_virtual_path[0] if current_virtual_path else self.fo_data.file_name

    def _has_children(self) -> bool:
        if self.whitelist:
            return any(f in self.fo_data.included_files for f in self.whitelist)
        return bool(self.fo_data.included_files)
