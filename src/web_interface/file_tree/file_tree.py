from __future__ import annotations

from itertools import chain
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Set

from web_interface.file_tree.file_tree_node import FileTreeNode

WEB_BASE_PATH = Path(__file__).parent.parent
ICON_PATH = WEB_BASE_PATH / 'static/file_icons/mimetypes'
TYPE_TO_PATH = {p.stem: f'/{p.relative_to(WEB_BASE_PATH)}' for p in ICON_PATH.iterdir()}
CRYPTO = 'application-certificate'
CONFIG = 'text-x-makefile'
TYPE_TO_PATH.update(
    {
        # MIME types
        'application-x-pie-executable': TYPE_TO_PATH['application-x-executable'],
        'application-x-dosexec': TYPE_TO_PATH['application-x-ms-dos-executable'],
        'linux-device-tree': '/static/file_icons/firmware.svg',
        # file suffixes
        'c': TYPE_TO_PATH['text-x-csrc'],
        'cert': TYPE_TO_PATH[CRYPTO],
        'cfg': TYPE_TO_PATH[CONFIG],
        'cnf': TYPE_TO_PATH[CONFIG],
        'conf': TYPE_TO_PATH[CONFIG],
        'control': TYPE_TO_PATH['application-x-deb'],
        'cpp': TYPE_TO_PATH['text-x-c++src'],
        'crt': TYPE_TO_PATH[CRYPTO],
        'eps': TYPE_TO_PATH['application-postscript'],
        'h': TYPE_TO_PATH['text-x-chdr'],
        'htm': TYPE_TO_PATH['text-html'],
        'image': TYPE_TO_PATH['package-x-generic'],
        'ini': TYPE_TO_PATH[CONFIG],
        'js': TYPE_TO_PATH['application-x-javascript'],
        'key': TYPE_TO_PATH['application-pgp'],
        'md': TYPE_TO_PATH['text-x-markdown'],
        'pem': TYPE_TO_PATH[CRYPTO],
        'pl': TYPE_TO_PATH['application-x-perl'],
        'properties': TYPE_TO_PATH['text-x-java'],
        'ps': TYPE_TO_PATH['application-postscript'],
        'pub': TYPE_TO_PATH['application-pgp'],
        'py': TYPE_TO_PATH['text-x-python'],
        'rb': TYPE_TO_PATH['application-x-ruby'],
        'sh': TYPE_TO_PATH['application-x-shellscript'],
        'svg': TYPE_TO_PATH['image-svg+xml'],
        'ts': TYPE_TO_PATH['application-x-javascript'],
        'xsd': TYPE_TO_PATH['text-xml'],
        'yml': TYPE_TO_PATH['application-x-yaml'],
    }
)
GNOME_PREFIX = 'gnome-mime-'
TYPE_TO_PATH.update(
    {
        k.replace(GNOME_PREFIX, ''): v
        for k, v in TYPE_TO_PATH.items()
        if k.startswith(GNOME_PREFIX) and k.replace(GNOME_PREFIX, '') not in TYPE_TO_PATH
    }
)
SPECIAL_FILES = {
    'authors': TYPE_TO_PATH['text-x-credits'],
    'license': TYPE_TO_PATH['text-x-copying'],
    'readme': TYPE_TO_PATH['text-x-readme'],
    'version': TYPE_TO_PATH['text-x-readme'],
}
SPECIAL_FILES.update({k.upper(): v for k, v in SPECIAL_FILES.items()})
SPECIAL_FILES.update({k.title(): v for k, v in SPECIAL_FILES.items()})
ARCHIVE_FILE_TYPES = [
    'application/java-archive',
    'application/rar',
    'application/x-adf',
    'application/x-alzip',
    'application/x-bzip2',
    'application/x-cab',
    'application/x-debian-package',
    'application/x-dms',
    'application/x-iso9660-image',
    'application/x-lrzip',
    'application/x-lzh',
    'application/x-lzip',
    'application/x-redhat-package-manager',
    'application/x-rzip',
    'application/x-shar',
    'application/x-sit',
    'application/x-sitx',
    'application/x-stuffitx',
    'application/x-xz',
    'application/x-zip-compressed',
    'application/zpaq',
    'compression/zlib',
]
TYPE_CATEGORY_TO_ICON = {
    'audio/': TYPE_TO_PATH['audio-x-generic'],
    'filesystem/': '/static/file_icons/filesystem.svg',
    'firmware/': '/static/file_icons/firmware.svg',
    'font/': TYPE_TO_PATH['font-x-generic'],
    'image/': TYPE_TO_PATH['image-x-generic'],
    'text/': TYPE_TO_PATH['text-x-generic'],
    'video/': TYPE_TO_PATH['video-x-generic'],
}


class FileTreeData(NamedTuple):
    uid: str
    file_name: str
    size: int
    virtual_file_path: Dict[str, List[str]]
    mime: str
    included_files: Set[str]


def get_icon_for_file(mime_type: Optional[str], file_name: str) -> str:
    '''
    Retrieve the path to the appropriate icon for a given mime type and file name. The icons are located in the static
    folder of the web interface and the paths therefore start with "/static". Archive types all receive the same icon.

    :param mime_type: The MIME type of the file (in the file tree).
    :param file_name: The file name.
    '''
    if mime_type is None:
        return TYPE_TO_PATH['unknown']
    if file_name in SPECIAL_FILES:
        return SPECIAL_FILES[file_name]
    # suffix may be there but mime is text/plain, so we check the suffix first
    suffix_icon = _find_icon_for_suffix(file_name)
    if suffix_icon:
        return suffix_icon
    if mime_type.replace('/', '-') in TYPE_TO_PATH:
        return TYPE_TO_PATH[mime_type.replace('/', '-')]
    if mime_type in ARCHIVE_FILE_TYPES:
        return TYPE_TO_PATH['package-x-generic']
    for mime_category, icon_path in TYPE_CATEGORY_TO_ICON.items():
        if mime_category in mime_type:
            return icon_path
    return TYPE_TO_PATH['unknown']


def _find_icon_for_suffix(file_name: str) -> str | None:
    suffix = Path(file_name).suffix.lstrip('.').lower()
    if not suffix:
        return None
    if suffix in TYPE_TO_PATH:
        return TYPE_TO_PATH[suffix]
    for prefix in ['text', 'text-x', 'application', 'application-x']:
        if f'{prefix}-{suffix}' in TYPE_TO_PATH:
            return TYPE_TO_PATH[f'{prefix}-{suffix}']
    return None


def _get_partial_virtual_paths(virtual_path: Dict[str, List[str]], new_root: str) -> List[str]:
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

    def __init__(self, root_uid: str, parent_uid: str, fo_data: FileTreeData, whitelist: Optional[List[str]] = None):
        self.uid = fo_data.uid
        self.root_uid = root_uid if root_uid else list(fo_data.virtual_file_path)[0]
        self.parent_uid = parent_uid
        self.fo_data: FileTreeData = fo_data
        self.whitelist = whitelist
        self.virtual_file_paths = self._get_virtual_file_paths()

    def _get_virtual_file_paths(self) -> List[str]:
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
            self.uid,
            self.root_uid,
            virtual=False,
            name=self._get_file_name(current_virtual_path),
            size=self.fo_data.size,
            mime_type=self.fo_data.mime,
            has_children=self._has_children(),
        )

    def _get_file_name(self, current_virtual_path: List[str]) -> str:
        return current_virtual_path[0] if current_virtual_path else self.fo_data.file_name

    def _has_children(self) -> bool:
        if self.whitelist:
            return any(f in self.fo_data.included_files for f in self.whitelist)
        return bool(self.fo_data.included_files)
