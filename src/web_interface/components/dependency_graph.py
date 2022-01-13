from contextlib import suppress
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
            groups.append(mime)

        virtual_paths = file['virtual_file_path'][root_uid]

        for vpath in virtual_paths:

            path_components = split_virtual_path(vpath)

            if len(path_components) < 2:
                continue

            name_component = path_components[-1]
            parent_component = path_components[-2]

            if parent_component != parent_uid:
                continue

            linked_libraries = []
            elf_analysis_missing = 'elf_analysis' not in file['processed_analysis']
            with suppress(KeyError):
                linked_libraries = file['processed_analysis']['elf_analysis']['Output']['libraries']

            node = {
                'label': name_component,
                'id': vpath,
                'entity': file['_id'],
                'group': mime,
                'full_file_type': file['processed_analysis']['file_type']['full'],
                'linked_libraries': linked_libraries,
                'elf_analysis_missing': elf_analysis_missing
            }

            data_graph['nodes'].append(node)

    data_graph['groups'] = sorted(groups)

    return data_graph


def create_data_graph_edges(data_graph):

    create_symbolic_link_edges(data_graph)
    elf_analysis_missing_from_files = 0

    for node in data_graph['nodes']:
        if node['elf_analysis_missing']:
            elf_analysis_missing_from_files += 1
            continue

        linked_libraries = node['linked_libraries']

        for linked_lib_name in linked_libraries:
            find_edges(node, linked_lib_name, data_graph)

    return data_graph, elf_analysis_missing_from_files


def create_symbolic_link_edges(data_graph):
    for node in data_graph['nodes']:
        if node['group'] == 'inode/symlink':
            link_to = Path(node['full_file_type'].split('\'')[1])

            if not link_to.is_absolute():
                base = Path(node['label']).parent
                link_to = normpath(base / link_to)

            for match in data_graph['nodes']:
                if match['label'] == str(link_to):
                    edge = {'from': node['id'], 'to': match['id'], 'id': len(data_graph['edges'])}
                    data_graph['edges'].append(edge)


def find_edges(node, linked_lib_name, data_graph):
    for lib in data_graph['nodes']:
        if linked_lib_name != Path(lib['label']).name:
            continue
        edge = {'from': node['id'], 'to': lib['id'], 'id': len(data_graph['edges'])}
        data_graph['edges'].append(edge)
        break


def get_graph_colors(quantity):
    return get_color_list(quantity, quantity) if quantity > 0 else []
