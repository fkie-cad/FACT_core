from __future__ import annotations

import datetime
from collections.abc import Iterable
from typing import Any, AnyStr, TypeVar

_KT = TypeVar('_KT')  # Key type
_VT = TypeVar('_VT')  # Value type


def make_bytes(data: AnyStr | list[int]) -> bytes:
    '''
    Convert `data` into bytes (if necessary).

    :param data: Some sort of data that can be converted to bytes.
    :return: The data as bytes.
    '''
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode('utf-8')
    return bytes(data)


def make_unicode_string(code: Any) -> str:
    '''
    Convert a (byte) string or some arbitrary object into a string.
    '''
    if isinstance(code, str):
        return code.encode(errors='replace').decode()
    if isinstance(code, bytes):
        return code.decode(errors='replace')
    return code.__str__()


def convert_uid_list_to_compare_id(uid_list: Iterable[str]) -> str:
    '''
    Convert a list of UIDs to a compare ID (which is a unique string consisting of UIDs separated by semi-colons, used
    to identify a FACT `Firmware` or `FileObject` comparison).

    :param uid_list: A list of `FileObject` or `Firmware` UIDs.
    :return: The compare ID.
    '''
    return ';'.join(sorted(uid_list))


def convert_compare_id_to_list(compare_id: str) -> list[str]:
    '''
    Convert a compare ID back to a list of UIDs.

    :param compare_id: The compare ID.
    :return: The according UID list.
    '''
    return compare_id.split(';')


def normalize_compare_id(compare_id: str) -> str:
    '''
    Sort the UIDs in a compare ID (so that it is unique) and return it.

    :param compare_id: The compare ID.
    :return: The according unique compare ID with reordered UIDs.
    '''
    uids = convert_compare_id_to_list(compare_id)
    return convert_uid_list_to_compare_id(uids)


def get_value_of_first_key(input_dict: dict[_KT, _VT]) -> _VT | None:
    '''
    Get the value of the first key in a dictionary. If the dict is empty, return `None`.

    :param input_dict: The dictionary to get the value from.
    :return: The value of the first key in the dictionary or `None` if it is empty.
    '''
    return input_dict[sorted(input_dict.keys())[0]] if input_dict else None


def none_to_none(input_data: str | None) -> str | None:
    '''
    Convert a string to `None` if it consists of the word `"None"` or return the input data otherwise.
    Used to convert a string coming from the web interface to a NoneType object if necessary.

    :param input_data: A string that may
    '''
    return None if input_data == 'None' else input_data


def convert_time_to_str(time_obj: Any) -> str:
    '''
    Convert a time object to a string. The time object may be a datetime.date object or a string. If it is anything else,
    the output defaults to `"1970-01-01"`.

    :param time_obj: The time object, that is converted to string.
    :return: The converted time object as string or a default date (if the conversion fails).
    '''
    if isinstance(time_obj, datetime.date):
        return time_obj.strftime('%Y-%m-%d')
    if isinstance(time_obj, str):
        return time_obj
    return '1970-01-01'


def convert_str_to_bool(string: str) -> bool:
    '''
    Convert a string to a boolean, e.g. `"0"` to `False` or `"Y"` to `True`.
    Replaces `distutils.util.strtobool` which was deprecated in Python 3.10.
    '''
    if not isinstance(string, str):
        raise ValueError(f'Expected type str and not {type(string)}')
    lower: str = string.lower()
    if lower in ('1', 'true', 't', 'yes', 'y'):
        return True
    if lower in ('0', 'false', 'f', 'no', 'n'):
        return False
    raise ValueError(f'Value {string} can not be converted to boolean')
