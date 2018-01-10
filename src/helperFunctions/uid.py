import re

from helperFunctions.dataConversion import make_bytes
from helperFunctions.hash import get_sha256


def create_uid(input_data):
    '''
    creates an unique identifier: SHA256_SIZE
    '''
    hash_value = get_sha256(input_data)
    size = len(make_bytes(input_data))
    return "{}_{}".format(hash_value, size)


def is_uid(input_string):
    '''
    returns true if input string is a valid uid
    returns false otherwise
    '''
    if not isinstance(input_string, str):
        return False
    else:
        match = re.match(r'[a-f0-9]{64}_[0-9]+', input_string)
        if match:
            if match.group(0) == input_string:
                return True
        return False


def is_list_of_uids(input_list):
    """
    returns true if list contains valid uids only
    returns false otherwise
    """
    if isinstance(input_list, set):
        input_list = list(input_list)
    if not isinstance(input_list, list):
        return False
    else:
        if len(input_list) == 0:
            return False
        for item in input_list:
            if not is_uid(item):
                return False
        return True
