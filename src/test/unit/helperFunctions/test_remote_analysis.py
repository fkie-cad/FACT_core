from collections import namedtuple
import time

import pytest

from helperFunctions.remote_analysis import create_task_id, parse_task_id, analysis_is_outdated, is_default_result, \
    check_that_result_is_complete, ResultCollisionError, deserialize, serialize
from objects.file import FileObject

UUID = namedtuple('UUID', ['hex'])


def test_create_task_id(monkeypatch):
    monkeypatch.setattr('uuid.uuid4', lambda: UUID(hex='ABC'))
    monkeypatch.setattr('calendar.timegm', lambda _: 123)
    uid = 'foo'
    task_id = create_task_id(uid)
    assert task_id == '123|ABC|foo'


def test_parse_task_id():
    task_id = '123|ABC|foo'
    uid, task, timestamp = parse_task_id(task_id)
    assert uid == 'foo'
    assert task == 'ABC'
    assert timestamp == '123'


def test_analysis_is_outdated_not_existing():
    test_object = FileObject()
    assert not analysis_is_outdated(test_object, 'any_analysis', time.time()), 'non existing analysis should be rescheduled'


def test_analysis_is_outdated_overwrite_result():
    test_object = FileObject()
    test_object.processed_analysis['any_analysis'] = dict(some_value='foo', summary=['bar'], analysis_date=0.0)
    assert analysis_is_outdated(test_object, 'any_analysis', 1.0)


def test_analysis_is_outdated_placeholder():
    test_object = FileObject()
    test_object.processed_analysis['any_analysis'] = dict(placeholder='foo', analysis_date=1000.0)
    assert analysis_is_outdated(test_object, 'any_analysis', 1.0)


def test_analysis_is_outdated_collision():
    test_object = FileObject()
    test_object.processed_analysis['any_analysis'] = dict(some_value='foo', summary=['bar'], analysis_date=2.0)
    with pytest.raises(ResultCollisionError):
        analysis_is_outdated(test_object, 'any_analysis', 1.0)


def test_is_default_result():
    assert not is_default_result({'any_result': 5})
    assert not is_default_result({})
    assert is_default_result({'placeholder': ['anything']})


@pytest.mark.parametrize('result', [None, {}, {'plugin_version': '0.0'}, {'analysis_date': 12.3}])
def test_check_result_is_complete_fails(result):
    with pytest.raises(ValueError):
        check_that_result_is_complete(result)


def test_check_result_is_complete_success():
    check_that_result_is_complete({'plugin_version': '0.0', 'analysis_date': 12.3})
    assert True, 'not raising means success, function has no return value'


def test_serialize():
    item = {'a_dict': ['with', b'a', 'list']}
    result = deserialize(serialize(item).encode())
    assert item == result
