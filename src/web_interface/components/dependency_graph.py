from itertools import chain, islice, repeat

from helperFunctions.web_interface import get_color_list


def create_data_graph_nodes_and_groups(data, whitelist):

    data_graph = {
        'nodes': [],
        'edges': [],
        'groups': []
    }
    groups = []

    for file_object in data:
        if file_object['processed_analysis']['file_type']['mime'] in whitelist:
            node = {
                'label': file_object['file_name'],
                'id': file_object['_id'],
                'group': file_object['processed_analysis']['file_type']['mime'],
                'full_file_type': file_object['processed_analysis']['file_type']['full']
            }

            if file_object['processed_analysis']['file_type']['mime'] not in groups:
                groups.append(file_object['processed_analysis']['file_type']['mime'])

            data_graph['nodes'].append(node)

    data_graph['groups'] = groups

    return data_graph


def create_data_graph_edges(data, data_graph):

    data_graph, edge_id = create_symbolic_link_edges(data_graph)

    for file_object in data:
        try:
            libraries = file_object['processed_analysis']['elf_analysis']['Output']['libraries']
        except (IndexError, KeyError):
            continue
        except TypeError:
            print(file_object['processed_analysis']['elf_analysis']['Output'])
            raise

        for lib in libraries:
            data_graph, edge_id = find_edges(data_graph, edge_id, lib, file_object)

    return data_graph


def create_symbolic_link_edges(data_graph):
    edge_id = 0

    for node in data_graph['nodes']:
        if node['group'] == 'inode/symlink':
            link_to = node['full_file_type'].split('\'')[1]
            for match in data_graph['nodes']:
                if match['label'] == link_to:
                    edge = {'source': node['id'], 'target': match['id'], 'id': edge_id}
                    data_graph['edges'].append(edge)
                    edge_id += 1
    return edge_id


def find_edges(data_graph, edge_id, lib, file_object):
    target_id = None

    for node in data_graph['nodes']:
        if node['label'] == lib:
            target_id = node['id']
    if target_id is not None:
        edge = {'source': file_object['_id'], 'target': target_id, 'id': edge_id}
        data_graph['edges'].append(edge)
        edge_id += 1

    return edge_id


def get_graph_colors():
    available_colors = get_color_list(10)
    color_list = list(islice(chain(*repeat(available_colors, 4)), None, None, 4))
    return color_list
