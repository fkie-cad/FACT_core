import base64
import calendar
import logging
import pickle
import time
import uuid

from objects.file import FileObject


class ResultCollisionError(RuntimeError):
    pass


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
    if not len(items) == 3:
        raise ValueError('task id has bad format. should be timestamp|task|uid.')
    timestamp, task, uid = items

    return uid, task, timestamp


def analysis_is_outdated(file_object: FileObject, analysis_system: str, timestamp: float) -> bool:
    '''
    Possible cases
    a) it doesn't even exist (the result generation was faster than the placeholder storage) -> Re-Queue (False)
    b) stored analysis date is older than the creation time of the new analysis -> Overwrite (True)
    c) it is only a placeholder result -> Overwrite (True)
    d) stored analysis date is newer than creation time of "new" analysis -> Runtime condition, drop result (Exception)
    '''
    if analysis_system not in file_object.processed_analysis:
        logging.warning('Default result has not been written to {}:{}. Real result might be overwritten later.'.format(file_object.get_uid(), analysis_system))
        return False
    if file_object.processed_analysis[analysis_system]['analysis_date'] < timestamp:
        return True
    if is_default_result(file_object.processed_analysis[analysis_system]):
        return True
    raise ResultCollisionError('New result already seems outdated and should be dropped')


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
    for assertion, error in [
        isinstance(result, dict), 'Result must be of type dict',
        'analysis_date' in result and isinstance(result['analysis_date'], float), 'No analysis date specified',
        'plugin_version' in result and isinstance(result['plugin_version'], str), 'No plugin version specified'
    ]:
        if not assertion:
            raise ValueError(error)


def serialize(item: dict) -> str:
    '''
    Convert message dict in string for rabbitMQ transmission
    '''
    return base64.standard_b64encode(pickle.dumps(item)).decode()


def deserialize(item: bytes) -> dict:
    '''
    Convert byte-string rabbitMQ transmission back to message dict
    '''
    return pickle.loads(base64.standard_b64decode(item))
