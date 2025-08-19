from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, AnyStr

from helperFunctions.data_conversion import make_bytes
from helperFunctions.hash import get_sha256

if TYPE_CHECKING:
    from helperFunctions.types import UID

UID_REGEX = re.compile(r'[a-f0-9]{64}_[0-9]+')


def create_uid(input_data: AnyStr) -> UID:
    """
    generate a UID (unique identifier) SHA256_SIZE for a byte string containing data (e.g. a binary)

    :param input_data: the data to generate the UID for
    :return: a string containing the UID
    """
    hash_value = get_sha256(input_data)
    size = len(make_bytes(input_data))
    return f'{hash_value}_{size}'


def is_uid(input_string: Any) -> bool:
    """
    Check if a string is a valid UID

    :param input_string: the string to check
    :return: true if input string is a valid uid and false otherwise
    """
    if not isinstance(input_string, str):
        return False
    match = UID_REGEX.match(input_string)
    if match and match.group(0) == input_string:
        return True
    return False


def is_list_of_uids(input_list: list | set) -> bool:
    """
    Checks if all elements of a list are valid UIDs

    :param input_list: the list to check
    :return: true if input list contains only valid UIDs and false otherwise
    """
    if isinstance(input_list, set):
        input_list = list(input_list)
    if not input_list or not isinstance(input_list, list):
        return False
    return all(is_uid(item) for item in input_list)
