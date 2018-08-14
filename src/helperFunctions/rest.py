import json
from copy import deepcopy
import time
import calendar


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


def get_paging(request_parameter):
    offset = request_parameter['offset'] if 'offset' in request_parameter else 0
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return 'Malformed offset parameter', False

    limit = request_parameter['limit'] if 'limit' in request_parameter else 0
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return 'Malformed limit parameter', False

    return (offset, limit), True


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


def get_recursive(request_parameter):
    try:
        recursive = request_parameter.get('recursive')
        recursive = json.loads(recursive if recursive else 'false')
    except (AttributeError, KeyError):
        return False
    except json.JSONDecodeError:
        raise ValueError('recursive must be true or false')

    if recursive not in [True, False]:
        raise ValueError('recursive must be true or false')
    return recursive


def get_update(request_parameter):
    try:
        update = request_parameter.get('update')
        update = json.loads(update if update else None)
    except (AttributeError, KeyError, TypeError):
        raise ValueError('Malformed or missing parameter: update')
    except json.JSONDecodeError:
        raise ValueError('Update parameter has to be a list')
    if not isinstance(update, list):
        raise ValueError('Update must be a list')
    if not update:
        raise ValueError('Update has to be specified')
    return update


def get_summary_flag(request_parameter):
    try:
        summary = request_parameter.get('summary')
        summary = json.loads(summary if summary else 'false')
    except (AttributeError, KeyError):
        return False
    except json.JSONDecodeError:
        raise ValueError('summary must be true or false')

    if summary not in [True, False]:
        raise ValueError('summary must be true or false')
    return summary


def get_tar_flag(request_parameter):
    tar_arg = request_parameter['tar'] if 'tar' in request_parameter else 'false'
    try:
        tar_flag = json.loads(tar_arg)
        if not isinstance(tar_flag, bool):
            raise TypeError()
    except (json.JSONDecodeError, TypeError):
        raise ValueError('Malformed tar parameter. Must be in {true, false}')

    return tar_flag
