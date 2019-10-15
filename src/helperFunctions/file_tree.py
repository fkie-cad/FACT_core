from typing import List

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


def get_correct_icon_for_mime(mime_type):
    if mime_type in ARCHIVE_FILE_TYPES:
        return '/static/file_icons/archive.png'
    if mime_type in TYPE_TO_ICON:
        return TYPE_TO_ICON[mime_type]
    for mime_category, icon_path in TYPE_CATEGORY_TO_ICON.items():
        if mime_category in mime_type:
            return icon_path
    return '/static/file_icons/unknown.png'


def get_partial_virtual_path(virtual_path, root):
    '''
    returns a partial virtual path with parameter root as the new root
    '''
    first_path = list(virtual_path.values())[0][0]
    if root not in first_path:
        return {root: ['|{}|'.format(root)]}
    first_path = first_path.split('|')
    index = first_path.index(root)
    return {root: ['|'.join([''] + first_path[index:])]}


class FileTreeNode:
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
        print('{}{} (virtual:{}, has_children:{})'.format(spacer, self.name, self.virtual, self.has_children))
        for child_node in self.children.values():
            child_node.print_tree(spacer=spacer + '\t|')

    def merge_node(self, node):
        current_node = self.children[node.get_id()]
        for child in node.get_list_of_child_nodes():
            if child in current_node:
                current_node.merge_node(child)
            else:
                current_node.add_child_node(child)

    def add_child_node(self, node):
        if node.get_id() in self.children:
            self.merge_node(node)
        else:
            self.has_children = True
            self.children[node.get_id()] = node

    def get_names_of_children(self):
        return [n.name for n in self.get_list_of_child_nodes()]

    def get_list_of_child_nodes(self):
        return list(self.children.values())

    def get_id(self):
        # files and folders may have the same name but folders are 'virtual' -> take both for unique key
        return self.name, self.virtual


def root_is_virtual(root: List[dict]) -> bool:
    try:
        return root[0]['a_attr'] == {'href': '#'}
    except (KeyError, IndexError):
        return False


def remove_virtual_path_from_root(root: List[dict]) -> List[dict]:
    '''
    when a file object is the root, the directories that contain the file object need to be removed so that the file
    tree is displayed correctly in the web interface
    '''
    while root_is_virtual(root):
        root = root[0]['children']
    return root
