"""
This module offers neat wrapper functionality for use in rest endpoints.
Most wrappers target request and response parsing.
"""

from __future__ import annotations

import calendar
import json
import time
from copy import deepcopy
from typing import Mapping


def get_current_gmt() -> int:
    """
    Get the current unix time. The system value might depend on NTP.

    :return: Current time as unix timestamp integer.
    """
    return int(calendar.timegm(time.gmtime()))


def success_message(
    data: dict, targeted_url: str, request_data: dict | None = None, return_code: int = 200
) -> tuple[dict, int]:
    """
    Create success response including requested data and useful meta information, such as the request parameters.

    :param data: dict containing the requested data.
    :param targeted_url: Requested URL.
    :param request_data: Parameters of the request.
    :param return_code: HTTP status code for response. Defaults to 200 OK.
    :return: dict containing a response adhering to the FACT rest api guidelines.
    """
    if not isinstance(data, dict):
        raise TypeError('data must be of type dict')
    message = deepcopy(data)

    message['timestamp'] = get_current_gmt()
    message['request_resource'] = targeted_url
    message['status'] = 0
    if request_data:
        message['request'] = request_data
    return message, return_code


def error_message(
    error: str, targeted_url: str, request_data: dict | None = None, return_code: int = 400
) -> tuple[dict, int]:
    """
    Create error response including error message and useful meta information, such as the request parameters.

    :param error: String containing a reason why the request failed.
    :param targeted_url: Requested URL.
    :param request_data: Parameters of the request.
    :param return_code: HTTP status code for response. Defaults to 400 Bad Request.
    :return: dict containing a response adhering to the FACT rest api guidelines.
    """
    if not isinstance(error, str):
        raise TypeError('error must be of type str')
    message = {'error_message': error}

    message['timestamp'] = get_current_gmt()
    message['request_resource'] = targeted_url
    message['status'] = 1
    if request_data:
        message['request'] = request_data
    return message, return_code


def get_paging(request_parameters: Mapping) -> tuple[int, int]:
    """
    Parse paging parameter offset and limit from request parameters.

    :param request_parameters: dict containing the request parameters.
    :return: The paging parameters offset and limit as integers.
    """
    try:
        offset = int(request_parameters.get('offset', 0))
    except (TypeError, ValueError) as error:
        raise ValueError('Malformed offset parameter') from error

    try:
        limit = int(request_parameters.get('limit', 0))
    except (TypeError, ValueError) as error:
        raise ValueError('Malformed limit parameter') from error

    return offset, limit


def get_json_field(request_parameters: Mapping, field: str) -> dict:
    """
    Parse the query parameter from request parameters. Query is a dictionary representing a MongoDB query.

    :param request_parameters: dict containing the request parameters.
    :param field: the JSON field to retrieve.
    :return: The MongoDB query as dict.
    """
    try:
        value = request_parameters.get(field)
        value = json.loads(value if value else '{}')
    except (AttributeError, KeyError):
        return {}
    except json.JSONDecodeError as error:
        raise ValueError(f'Field "{field}" must be a json document') from error
    if not isinstance(value, dict):
        raise ValueError(f'Field "{field}" must be a json document')
    return value if value else {}


def get_boolean_from_request(request_parameters: Mapping, name: str) -> bool:
    """
    Retrieve a specific flag from the request parameters as a boolean.

    :param request_parameters: dict containing the request parameters.
    :param name: Identifier of the flag that is to be retrieved.
    :return: The retrieved flag as boolean.
    """
    try:
        parameter = json.loads(request_parameters.get(name, 'false'))
        if not isinstance(parameter, bool):
            raise TypeError()
    except (AttributeError, KeyError):
        return False
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError(f'{name} must be true or false') from error
    return parameter


def get_update(request_parameters: Mapping) -> list:
    """
    Parse the update parameter from request parameters. Update is a list of analysis plugins whose analysis results
    shall be updated.

    :param request_parameters: dict containing the request parameters.
    :return: The list of analysis plugins.
    """
    try:
        update = json.loads(request_parameters.get('update'))
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError('Malformed or missing parameter: update') from error
    except json.JSONDecodeError as error:
        raise ValueError('Update parameter has to be a list') from error
    if not isinstance(update, list):
        raise ValueError('Update must be a list')
    if not update:
        raise ValueError('Update has to be specified')
    return update
