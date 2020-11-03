from typing import Union

import yaml


def _parse_yaml(file_path: str) -> Union[dict, list, None]:
    '''
    Opens a yaml file, parses its contents and returns a python object or ``None`` if not successful.

    :param file_path: The path to the yaml file.
    :return: The loaded contents of the yaml file or None.
    '''
    with open(file_path, 'r') as fd:
        data = yaml.safe_load(fd)
    return data


def get_mongo_path(file_path: str) -> str:
    '''
    Retrieve the MongoDB database path from the (yaml) config file.

    :param file_path: The path to the MongoDB config file.
    :return: The MongoDB database path.
    '''
    data = _parse_yaml(file_path)
    return data['storage']['dbPath']
