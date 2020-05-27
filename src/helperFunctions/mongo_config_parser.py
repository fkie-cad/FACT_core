import yaml


def parse_yaml(file_path):
    with open(file_path, 'r') as fd:
        data = yaml.safe_load(fd)

    return data
