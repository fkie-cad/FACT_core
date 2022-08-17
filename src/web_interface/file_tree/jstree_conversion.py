from common_helper_files import human_readable_file_size

from web_interface.file_tree.file_tree import get_correct_icon_for_mime
from web_interface.file_tree.file_tree_node import FileTreeNode


def convert_to_jstree_node(node: FileTreeNode):
    '''
    converts a file tree node to a json dict that can be rendered by jstree

    :param node: the file tree node
    :return: a json-compatible dict containing the jstree data
    '''
    if node.virtual:
        jstree_node = _get_directory_jstree_node(node)
    elif node.not_analyzed:
        jstree_node = _get_not_analyzed_jstree_node(node)
    else:
        jstree_node = _get_file_jstree_node(node)
    if node.has_children:
        jstree_node['children'] = _get_jstree_child_nodes(node)
    return jstree_node


def _get_directory_jstree_node(node: FileTreeNode):
    return _get_jstree_node_contents(f'{node.name}', '#', '/static/file_icons/folder.png')


def _get_not_analyzed_jstree_node(node: FileTreeNode):
    link = f'/analysis/{node.uid}/ro/{node.root_uid}'
    return _get_jstree_node_contents(f'{node.name}', link, '/static/file_icons/not_analyzed.png')


def _get_file_jstree_node(node: FileTreeNode):
    link = f'/analysis/{node.uid}/ro/{node.root_uid}'
    label = f'<b>{node.name}</b> (<span style="color:gray;">{human_readable_file_size(node.size)}</span>)'
    result = _get_jstree_node_contents(label, link, get_correct_icon_for_mime(node.type))
    result['data'] = {'uid': node.uid}
    return result


def _get_jstree_child_nodes(node: FileTreeNode):
    child_nodes = node.get_list_of_child_nodes()
    if not child_nodes:
        return True
    result = []
    for child in child_nodes:
        result_child = convert_to_jstree_node(child)
        if result_child is not None:
            result.append(result_child)
    return result


def _get_jstree_node_contents(text: str, link: str, icon: str) -> dict:
    return {
        'text': text,
        'a_attr': {'href': link},
        'li_attr': {'href': link},
        'icon': icon,
    }
