import logging
from itertools import chain
from typing import Dict, Iterable, List, Optional, Tuple

ARCHIVE_FILE_TYPES = [
    'application/gzip', 'application/java-archive', 'application/rar', 'application/vnd.ms-cab-compressed',
    'application/x-7z-compressed', 'application/x-ace', 'application/x-adf', 'application/x-alzip', 'application/x-arc',
    'application/x-archive', 'application/x-arj', 'application/x-bzip2', 'application/x-cab', 'application/x-chm',
    'application/x-compress', 'application/x-cpio', 'application/x-debian-package', 'application/x-dms',
    'application/x-gzip', 'application/x-iso9660-image', 'application/x-lha', 'application/x-lrzip',
    'application/x-lzh', 'application/x-lzip', 'application/x-lzma', 'application/x-lzop', 'application/x-rar',
    'application/x-redhat-package-manager', 'application/x-rpm', 'application/x-rzip', 'application/x-shar',
    'application/x-sit', 'application/x-sitx', 'application/x-stuffit', 'application/x-stuffitx', 'application/x-tar',
    'application/x-xz', 'application/x-zip-compressed', 'application/x-zoo', 'application/zip', 'application/zpaq',
    'audio/flac', 'compression/zlib'
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


def get_correct_icon_for_mime(mime_type: str) -> str:
    '''
    Retrieve the path to appropriate icon for a given mime type. The icons are located in the static folder of the
    web interface and the paths therefore start with "/static". Archive types all receive the same icon.

    :param mime_type: The MIME type of a file (in the file tree).
    '''
    if mime_type in ARCHIVE_FILE_TYPES:
        return '/static/file_icons/archive.png'
    if mime_type in TYPE_TO_ICON:
        return TYPE_TO_ICON[mime_type]
    for mime_category, icon_path in TYPE_CATEGORY_TO_ICON.items():
        if mime_category in mime_type:
            return icon_path
    return '/static/file_icons/unknown.png'


def _get_partial_virtual_paths(virtual_path: Dict[str, List[str]], new_root: str) -> List[str]:
    '''
    Returns a list of new partial virtual paths with ``new_root`` as the new root element.
    If no paths containing ``new_root`` are found, a fallback path is created, consisting only of ``new_root``.
    '''
    paths_with_new_root = {
        _get_vpath_relative_to(vpath, new_root)
        for vpath in chain(*virtual_path.values())
        if new_root in vpath
    }
    if not paths_with_new_root:
        return ['|{uid}|'.format(uid=new_root)]
    return sorted(paths_with_new_root)


def _get_vpath_relative_to(virtual_path: str, uid: str):
    vpath_elements = virtual_path.split('|')
    index = vpath_elements.index(uid)
    return '|'.join([''] + vpath_elements[index:])


class FileTreeNode:  # pylint: disable=too-many-instance-attributes,too-many-arguments
    '''
    A Node in the File Tree, representing either a file or a directory.

    :param uid: The uid for the file or ``None`` in case of a directory.
    :param root_uid: The uid of the root file in the file tree.
    :param virtual: Is ``False`` for files and ``True`` for directories (which are only elements of the not really
    '''
    def __init__(self, uid, root_uid=None, virtual=False, name=None, size=None, mime_type=None, has_children=False,
                 not_analyzed=False):
        self.uid = uid
        self.root_uid = root_uid
        self.virtual = virtual
        self.name = name
        self.size = size
        self.type = mime_type
        self.has_children = has_children
        self.not_analyzed = not_analyzed
        self.children = {}

    def __str__(self):
        return 'Node \'{}\' with children {}'.format(self.name, self.get_names_of_children())

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.uid == other.uid and self.name == other.name and self.virtual == other.virtual

    def __contains__(self, item):
        return item.get_id() in self.children

    def print_tree(self, spacer=''):
        '''
        Print the file tree (used mainly for debugging).
        '''
        logging.info('{}{} (virtual:{}, has_children:{})'.format(spacer, self.name, self.virtual, self.has_children))
        for child_node in self.children.values():
            child_node.print_tree(spacer=spacer + '\t|')

    def merge_node(self, node: 'FileTreeNode'):
        '''
        Merge subtrees recursively.

        :param node: A file tree node.
        '''
        current_node = self.children[node.get_id()]
        for child in node.get_list_of_child_nodes():
            if child in current_node:
                current_node.merge_node(child)
            else:
                current_node.add_child_node(child)

    def add_child_node(self, node: 'FileTreeNode'):
        '''
        Add a given node to the current node as a child (in the file tree).

        :param node: A file tree node.
        '''
        if node in self:
            self.merge_node(node)
        else:
            self.has_children = True
            self.children[node.get_id()] = node

    def get_names_of_children(self) -> List[str]:
        return [n.name for n in self.get_list_of_child_nodes()]

    def get_list_of_child_nodes(self) -> List['FileTreeNode']:
        '''
        Get a list of the child nodes of the file tree node.
        '''
        return list(self.children.values())

    def get_id(self) -> Tuple[str, bool]:
        '''
        Get a unique id of the node. Files and folders may have the same name but folders are 'virtual' -> take both
        as a unique id.

        :return: The id, consisting of the name and
        '''
        return self.name, self.virtual


def _root_is_virtual(root: List[dict]) -> bool:
    try:
        return root[0]['a_attr'] == {'href': '#'}
    except (KeyError, IndexError):
        return False


def remove_virtual_path_from_root(root: List[dict]) -> List[dict]:
    '''
    When a file object is the root, the directories that contain the file object need to be removed so that the file
    tree is displayed correctly in the web interface.
    '''
    while _root_is_virtual(root):
        root = root[0]['children']
    return root


class VirtualPathFileTree:
    '''
    This class represents a layer or the  file tree  with a ``Firmware`` or ``FileObject`` as root, directories as
    inner vertices and  ``FileObject``s as outer vertices. It consists of vertices of type ``FileTreeNode``.
    '''

    #: Required fields for a database query to build the file tree.
    FO_DATA_FIELDS = {
        '_id': 1, 'file_name': 1, 'files_included': 1, 'processed_analysis.file_type.mime': 1, 'size': 1,
        'virtual_file_path': 1,
    }

    def __init__(self, root_uid: str, fo_data: dict, whitelist: Optional[List[str]] = None):
        self.uid = fo_data['_id']
        self.root_uid = root_uid if root_uid else list(fo_data['virtual_file_path'])[0]
        self.fo_data = fo_data
        self.whitelist = whitelist
        self.virtual_file_paths = self._get_virtual_file_paths()

    def _get_virtual_file_paths(self) -> List[str]:
        if self._file_tree_is_for_file_object():
            return _get_partial_virtual_paths(self.fo_data['virtual_file_path'], self.root_uid)
        return self.fo_data['virtual_file_path'][self.root_uid]

    def _file_tree_is_for_file_object(self) -> bool:
        return self.root_uid not in self.fo_data['virtual_file_path']

    def get_file_tree_nodes(self) -> Iterable[FileTreeNode]:
        '''
        Create ``FileTreeNode`` s for the elements of the root's virtual file path. The same file may occur several
        times with different virtual paths. Returns a sequence of nodes, representing the subsequent layer in the
        file tree (which themselves may contain child nodes).

        :return: An iterable sequence of nodes of the file tree.
        '''
        for virtual_path in self.virtual_file_paths:
            yield self._create_node_from_virtual_path(virtual_path.split('/')[1:])

    def _create_node_from_virtual_path(self, current_virtual_path: List[str]) -> FileTreeNode:
        if len(current_virtual_path) > 1:
            return self._get_node_for_virtual_file(current_virtual_path)
        return self._get_node_for_real_file(current_virtual_path)

    def _get_node_for_virtual_file(self, current_virtual_path: List[str]) -> FileTreeNode:
        current_element, *rest_of_virtual_path = current_virtual_path
        node = FileTreeNode(uid=None, root_uid=self.root_uid, virtual=True, name=current_element)
        node.add_child_node(self._create_node_from_virtual_path(rest_of_virtual_path))
        return node

    def _get_node_for_real_file(self, current_virtual_path: List[str]) -> FileTreeNode:
        return FileTreeNode(
            self.uid, self.root_uid, virtual=False, name=self._get_file_name(current_virtual_path),
            size=self.fo_data['size'], mime_type=self._get_mime_type(), has_children=self._has_children()
        )

    def _get_mime_type(self) -> str:
        return self.fo_data['processed_analysis'].get('file_type', {'mime': 'file-type-plugin/not-run-yet'}).get('mime')

    def _get_file_name(self, current_virtual_path: List[str]) -> str:
        return current_virtual_path[0] if current_virtual_path else self.fo_data['file_name']

    def _has_children(self) -> bool:
        if self.whitelist:
            return any(f in self.fo_data['files_included'] for f in self.whitelist)
        return self.fo_data['files_included'] != []
