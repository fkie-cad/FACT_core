from typing import List, NamedTuple, Optional

from helperFunctions.web_interface import get_color_list


class DepGraphData(NamedTuple):
    uid: str
    file_name: str
    mime: str
    full_type: str
    libraries: Optional[List[str]] = None


def create_data_graph_nodes_and_groups(dependency_data: List[DepGraphData], whitelist):
    data_graph = {
        'nodes': [],
        'edges': []
    }
    groups = set()

    for entry in dependency_data:
        if entry.mime in whitelist:
            node = {
                'label': entry.file_name,
                'id': entry.uid,
                'group': entry.mime,
                'full_file_type': entry.full_type
            }
            groups.add(entry.mime)
            data_graph['nodes'].append(node)

    data_graph['groups'] = sorted(groups)

    return data_graph


def create_data_graph_edges(dependency_data: List[DepGraphData], data_graph: dict):

    edge_id = _create_symbolic_link_edges(data_graph)
    elf_analysis_missing_from_files = 0

    for entry in dependency_data:
        if entry.libraries is None:
            elf_analysis_missing_from_files += 1
            continue

        for lib in entry.libraries:
            edge_id = _find_edges(data_graph, edge_id, lib, entry.uid)

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
