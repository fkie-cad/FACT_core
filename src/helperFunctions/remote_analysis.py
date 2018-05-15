import calendar
import logging
import time
import uuid

from objects.file import FileObject


def create_task_id(uid: str) -> str:
    '''
    Create unique task id for scheduling
    '''
    return '{timestamp}|{task}|{uid}'.format(
        timestamp=int(calendar.timegm(time.gmtime())),
        task=uuid.uuid4().hex,
        uid=uid
    )


def parse_task_id(task_id: str) -> tuple:
    '''
    Get uid, task and timestamp from task id
    '''
    items = task_id.split('|')
    assert len(items) == 3, 'task id has bad format'
    timestamp, task, uid = items

    return uid, task, timestamp


def analysis_is_outdated(file_object: FileObject, analysis_system: str, timestamp: float) -> bool:
    '''
    "Existing" analysis is outdated if
    a) it doesn't even exist (which would probably mean there was an error ..)
    b) its analysis date is older than the creation time of the new analysis
    c) it is only a placeholder result
    '''
    if analysis_system not in file_object.processed_analysis:
        logging.warning('Default result has not been written to {}:{}. Real result might be overwritten later.'.format(file_object.get_uid(), analysis_system))
        return True
    if file_object.processed_analysis[analysis_system]['analysis_date'] > timestamp:
        return True
    if is_default_result(file_object.processed_analysis[analysis_system]):
        return True
    return False


def is_default_result(analysis_result: dict) -> bool:
    '''
    Plugins front-ending a remote analysis should store a placeholder result
    under the key placeholder to signify needing to be replaced by the remote result
    '''
    return 'placeholder' in analysis_result


def check_that_result_is_complete(result: dict) -> None:
    '''
    Raise an error if date and version were not set by the remote system or the result is not a dictionary
    '''
    try:
        assert isinstance(result, dict), 'Result must be of type dict'
        assert 'analysis_date' in result and isinstance(result['analysis_date'], float), 'No analysis date specified'
        assert 'plugin_version' in result and isinstance(result['plugin_version'], str), 'No plugin version specified'
    except AssertionError as assertion_error:
        raise ValueError(str(assertion_error))
