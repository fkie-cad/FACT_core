from collections import namedtuple

import pytest

from analysis.remote_plugin_base import RemoteBasePlugin
from helperFunctions.config import get_config_for_testing
from objects.file import FileObject

DEFAULT_NAME = 'Remote_Base_Plugin'

Admin = namedtuple('Admin', ['register_plugin'])


class MockChannel:
    def exchange_declare(self, *_, **__):
        pass

    def basic_publish(self, *_, **__):
        pass


@pytest.fixture(scope='function')
def plugin_base(monkeypatch):
    monkeypatch.setattr('pika.ConnectionParameters.__init__', lambda *_, **__: None)
    monkeypatch.setattr('pika.BlockingConnection.__init__', lambda *_, **__: None)
    monkeypatch.setattr('pika.BlockingConnection.channel', lambda *_, **__: MockChannel())
    monkeypatch.setattr('pika.BlockingConnection.close', lambda *_, **__: None)

    plugin = RemoteBasePlugin(plugin_administrator=Admin(register_plugin=lambda *_: None), config=get_config_for_testing())
    yield plugin
    plugin.shutdown()


@pytest.fixture(scope='function')
def stub_object():
    return FileObject()


def test_get_topic(plugin_base):
    assert 'analysis.{}.normal'.format(DEFAULT_NAME) == plugin_base._get_topic()


def test_get_dependencies_empty(plugin_base, stub_object):
    assert dict() == plugin_base._get_dependencies(stub_object)

    plugin_base.DEPENDENCIES = ['foo']

    with pytest.raises(KeyError):
        plugin_base._get_dependencies(stub_object)


def test_get_dependencies_existing(plugin_base, stub_object):
    stub_object.processed_analysis = {'foo': {'result': 'bar'}}
    plugin_base.DEPENDENCIES = ['foo']

    assert stub_object.processed_analysis == plugin_base._get_dependencies(stub_object)


def test_get_placeholder(plugin_base):
    assert isinstance(plugin_base._get_placeholder(), str)


def test_process_object(plugin_base, stub_object):
    plugin_base.process_object(stub_object)
    assert stub_object.processed_analysis[DEFAULT_NAME] == {'placeholder': plugin_base._get_placeholder()}
