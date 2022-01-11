from os.path import normpath
from pathlib import Path

from helperFunctions.virtual_file_path import split_virtual_path
from helperFunctions.web_interface import get_color_list


def create_data_graph_nodes_and_groups(data, parent_uid, root_uid, whitelist):

    data_graph = {
        'nodes': [],
        'edges': [],
        'groups': []
    }
    groups = []

    for file in data:
        mime = file['processed_analysis']['file_type']['mime']
        if mime not in whitelist or root_uid not in file['virtual_file_path']:
            continue

        if mime not in groups:
            groups.append(file['processed_analysis']['file_type']['mime'])
 
        virtual_paths = file['virtual_file_path'][root_uid]

        for vpath in virtual_paths:

            path_components = split_virtual_path(vpath)

            if len(path_components) < 2:
                continue

            name_component = path_components[-1]
            parent_component = path_components[-2]

            if parent_component != parent_uid:
                continue

            node = {
                'label': name_component,
                'id': vpath,
                'entity': file['_id'],
                'group': file['processed_analysis']['file_type']['mime'],
                'full_file_type': file['processed_analysis']['file_type']['full']
            }

            data_graph['nodes'].append(node)

    data_graph['groups'] = sorted(groups)

    return data_graph


def create_data_graph_edges(data, data_graph):

    edge_id = create_symbolic_link_edges(data_graph)
    elf_analysis_missing_from_files = 0

    for file in data:
        try:
            libraries = file['processed_analysis']['elf_analysis']['Output']['libraries']
        except (IndexError, KeyError):
            if 'elf_analysis' not in file['processed_analysis']:
                elf_analysis_missing_from_files += 1
            continue

        for lib in libraries:
            edge_id = find_edges(data_graph, edge_id, lib, file)

    return data_graph, elf_analysis_missing_from_files


def create_symbolic_link_edges(data_graph):
    edge_id = 0

    for node in data_graph['nodes']:
        if node['group'] == 'inode/symlink':
            link_to = Path(node['full_file_type'].split('\'')[1])

            import logging
            if not link_to.is_absolute():
                base = Path(node['label']).parent
                link_to = normpath(base / link_to)

            logging.warn(link_to)
            for match in data_graph['nodes']:
                if match['label'] == str(link_to):
                    edge = {'from': node['id'], 'to': match['id'], 'id': edge_id}
                    data_graph['edges'].append(edge)
                    edge_id += 1
    return edge_id


def find_edges(data_graph, edge_id, lib, file_object):
    target_id = None

    for node in data_graph['nodes']:
        if node['label'] == lib:
            target_id = node['id']
            break
    if target_id is not None:
        edge = {'from': file_object['_id'], 'to': target_id, 'id': edge_id}
        data_graph['edges'].append(edge)
        edge_id += 1

    return edge_id


def get_graph_colors(quantity):
    return get_color_list(quantity, quantity) if quantity > 0 else []
