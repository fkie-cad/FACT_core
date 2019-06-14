import yaml


def parse_yaml(file_path):
    with open(file_path, 'r') as fd:
        data = yaml.safe_load(fd)

    return data


def get_mongo_path(file_path):
    data = parse_yaml(file_path)
    return data['storage']['dbPath']
