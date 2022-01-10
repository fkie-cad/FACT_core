from typing import List

from helperFunctions.web_interface import get_color_list
from objects.file import FileObject


def create_data_graph_nodes_and_groups(fo_list: List[FileObject], whitelist):
    data_graph = {
        'nodes': [],
        'edges': []
    }
    groups = set()

    for fo in fo_list:
        mime = fo.processed_analysis['file_type']['mime']
        if mime in whitelist:
            node = {
                'label': fo.file_name,
                'id': fo.uid,
                'group': mime,
                'full_file_type': fo.processed_analysis['file_type']['full']
            }
            groups.add(mime)
            data_graph['nodes'].append(node)

    data_graph['groups'] = sorted(groups)

    return data_graph


def create_data_graph_edges(fo_list: List[FileObject], data_graph: dict):

    edge_id = _create_symbolic_link_edges(data_graph)
    elf_analysis_missing_from_files = 0

    for fo in fo_list:
        try:
            libraries = fo.processed_analysis['elf_analysis']['Output']['libraries']
        except (IndexError, KeyError):
            if 'elf_analysis' not in fo.processed_analysis:
                elf_analysis_missing_from_files += 1
            continue

        for lib in libraries:
            edge_id = _find_edges(data_graph, edge_id, lib, fo.uid)

    return data_graph, elf_analysis_missing_from_files


def _create_symbolic_link_edges(data_graph):
    edge_id = 0

    for node in data_graph['nodes']:
        if node['group'] == 'inode/symlink':
            link_to = node['full_file_type'].split('\'')[1]
            for match in data_graph['nodes']:
                if match['label'] == link_to:
                    edge = {'from': node['id'], 'to': match['id'], 'id': edge_id}
                    data_graph['edges'].append(edge)
                    edge_id += 1
    return edge_id


def _find_edges(data_graph, edge_id, lib, uid):
    target_id = None

    for node in data_graph['nodes']:
        if node['label'] == lib:
            target_id = node['id']
            break
    if target_id is not None:
        edge = {'from': uid, 'to': target_id, 'id': edge_id}
        data_graph['edges'].append(edge)
        edge_id += 1

    return edge_id


def get_graph_colors(quantity):
    return get_color_list(quantity, quantity) if quantity > 0 else []
