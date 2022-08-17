import logging
from typing import List, Tuple


class FileTreeNode:  # pylint: disable=too-many-instance-attributes,too-many-arguments
    '''
    A Node in the File Tree, representing either a file or a directory.

    :param uid: The uid for the file or ``None`` in case of a directory.
    :param root_uid: The uid of the root file in the file tree.
    :param virtual: Is ``False`` for files and ``True`` for directories (which are only elements of the not really
    :param name: Name of the file tree entry (i.e. file or directory name).
    :param size: The file size in bytes.
    :param mime_type: The MIME type of the file.
    :param has_children: Is ``True`` if there are nodes in the file tree below this one and ``False`` otherwise.
    :param not_analyzed: Is ``True`` if the analysis of the file is not complete and ``False`` otherwise.
    '''
    def __init__(
        self,
        uid,
        root_uid=None,
        virtual=False,
        name=None,
        size=None,
        mime_type=None,
        has_children=False,
        not_analyzed=False
    ):
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
        logging.info(f'{spacer}{self.name} (virtual:{self.virtual}, has_children:{self.has_children})')
        for child_node in self.children.values():
            child_node.print_tree(spacer=spacer + '\t|')

    def merge_node(self, node: 'FileTreeNode'):
        '''
        Merge subtrees recursively. Needed for nodes that were generated from files in the same directory.

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
        '''
        Get a list with the names of all child nodes of this node.

        :return: A list with the names of the children.
        '''
        return [n.name for n in self.get_list_of_child_nodes()]

    def get_list_of_child_nodes(self) -> List['FileTreeNode']:
        '''
        Get a list of the child nodes of this file tree node.

        :return: The child nodes.
        '''
        return list(self.children.values())

    def get_id(self) -> Tuple[str, bool]:
        '''
        Get a unique id of the node. Files and folders may have the same name but folders are 'virtual' -> take both
        as a unique id.

        :return: The id, consisting of the name and ``virtual`` (whether the node is a directory)
        '''
        return self.name, self.virtual
