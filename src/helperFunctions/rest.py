import calendar
import json
import time
from copy import deepcopy
from typing import Dict, Tuple


def get_current_gmt():
    # Note that NTP can mess with this
    return int(calendar.timegm(time.gmtime()))


def success_message(data, targeted_url, request_data=None, return_code=200):
    if not isinstance(data, dict):
        raise TypeError('data must be of type dict')
    message = deepcopy(data)

    message['timestamp'] = get_current_gmt()
    message['request_resource'] = targeted_url
    message['status'] = 0
    if request_data:
        message['request'] = request_data
    return message, return_code


def error_message(error, targeted_url, request_data=None, return_code=400):
    if not isinstance(error, str):
        raise TypeError('error must be of type str')
    message = dict(error_message=error)

    message['timestamp'] = get_current_gmt()
    message['request_resource'] = targeted_url
    message['status'] = 1
    if request_data:
        message['request'] = request_data
    return message, return_code


def convert_rest_request(data=None):
    try:
        test_dict = json.loads(data.decode())
        return test_dict
    except json.JSONDecodeError:
        raise TypeError('Request should be a dict !')
    except (AttributeError, UnicodeDecodeError) as error:
        raise TypeError(str(error))


def get_paging(request_parameters: Dict[str, object]) -> Tuple[int, int]:
    try:
        offset = int(request_parameters.get('offset', 0))
    except (TypeError, ValueError):
        raise ValueError('Malformed offset parameter')

    try:
        limit = int(request_parameters.get('limit', 0))
    except (TypeError, ValueError):
        raise ValueError('Malformed limit parameter')

    return offset, limit


def get_query(request_parameter):
    try:
        query = request_parameter.get('query')
        query = json.loads(query if query else '{}')
    except (AttributeError, KeyError):
        return dict()
    except json.JSONDecodeError:
        raise ValueError('Query must be a json document')
    if not isinstance(query, dict):
        raise ValueError('Query must be a json document')
    return query if query else dict()


def _get_boolean_from_request(request_parameters: Dict[str, object], name: str) -> bool:
    try:
        parameter = json.loads(request_parameters.get(name, 'false'))
        if not isinstance(parameter, bool):
            raise TypeError()
    except (AttributeError, KeyError):
        return False
    except (json.JSONDecodeError, TypeError):
        raise ValueError('{} must be true or false'.format(name))
    return parameter


def get_tar_flag(request_parameters):
    return _get_boolean_from_request(request_parameters, 'tar')


def get_summary_flag(request_parameters):
    return _get_boolean_from_request(request_parameters, 'summary')


def get_recursive_flag(request_parameters):
    return _get_boolean_from_request(request_parameters, 'recursive')


def get_inverted_flag(request_parameters):
    return _get_boolean_from_request(request_parameters, 'inverted')


def get_update(request_parameter):
    try:
        update = json.loads(request_parameter.get('update'))
    except (AttributeError, KeyError, TypeError):
        raise ValueError('Malformed or missing parameter: update')
    except json.JSONDecodeError:
        raise ValueError('Update parameter has to be a list')
    if not isinstance(update, list):
        raise ValueError('Update must be a list')
    if not update:
        raise ValueError('Update has to be specified')
    return update
