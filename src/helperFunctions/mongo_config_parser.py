from helperFunctions.process import complete_shutdown

try:
    import yaml
except ImportError:
    complete_shutdown("Could not load pyOpenSSL: Install it via: pip3 install pyyaml")


def parse_yaml(file_path):
    with open(file_path, 'r') as fd:
        data = yaml.load(fd)

    return data


def get_mongo_path(file_path):
    data = parse_yaml(file_path)
    return data['storage']['dbPath']
