from os.path import normpath
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

from helperFunctions.virtual_file_path import split_virtual_path
from helperFunctions.web_interface import get_color_list


class DepGraphData(NamedTuple):
    uid: str
    file_name: str
    virtual_file_paths: Dict[str, List[str]]
    mime: str
    full_type: str
    libraries: Optional[List[str]] = None


def create_data_graph_nodes_and_groups(dependency_data: List[DepGraphData], parent_uid, root_uid, whitelist):
    data_graph = {'nodes': [], 'edges': []}
    groups = set()

    for entry in dependency_data:
        if entry.mime not in whitelist or root_uid not in entry.virtual_file_paths:
            continue

        groups.add(entry.mime)

        virtual_paths = entry.virtual_file_paths[root_uid]

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
                'entity': entry.uid,
                'group': entry.mime,
                'full_file_type': entry.full_type,
                'linked_libraries': entry.libraries or [],
                'elf_analysis_missing': entry.libraries is None,
            }

            data_graph['nodes'].append(node)

    data_graph['groups'] = sorted(groups)

    return data_graph


def create_data_graph_edges(data_graph: dict):

    create_symbolic_link_edges(data_graph)
    elf_analysis_missing_from_files = 0

    for node in data_graph['nodes']:
        if node['elf_analysis_missing']:
            elf_analysis_missing_from_files += 1
            continue

        linked_libraries = node['linked_libraries']

        for linked_lib_name in linked_libraries:
            _find_edges(node, linked_lib_name, data_graph)

    return data_graph, elf_analysis_missing_from_files


def create_symbolic_link_edges(data_graph: dict):
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


def _find_edges(node, linked_lib_name, data_graph):
    for lib in data_graph['nodes']:
        if linked_lib_name != Path(lib['label']).name:
            continue
        edge = {'from': node['id'], 'to': lib['id'], 'id': len(data_graph['edges'])}
        data_graph['edges'].append(edge)
        break


def get_graph_colors(quantity):
    return get_color_list(quantity, quantity) if quantity > 0 else []
