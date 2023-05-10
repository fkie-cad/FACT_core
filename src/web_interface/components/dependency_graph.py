from __future__ import annotations

from os.path import normpath
from pathlib import Path
from typing import NamedTuple

from helperFunctions.web_interface import get_color_list


class DepGraphData(NamedTuple):
    uid: str
    file_name: str
    virtual_file_paths: list[str]
    mime: str
    full_type: str
    libraries: list[str] | None = None


def create_data_graph_nodes_and_groups(dependency_data: list[DepGraphData], whitelist):
    data_graph = {'nodes': [], 'edges': []}
    groups = set()

    for entry in dependency_data:
        if entry.mime not in whitelist or not entry.virtual_file_paths:
            continue
        groups.add(entry.mime)

        for vpath in entry.virtual_file_paths:
            node = {
                'label': vpath,
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
