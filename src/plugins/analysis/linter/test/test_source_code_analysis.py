from pathlib import Path

import pytest
from docker.errors import DockerException
from requests import ReadTimeout

from test.common_helper import create_test_file_object, get_config_for_testing

from ..code.source_code_analysis import AnalysisPlugin

# pylint: disable=redefined-outer-name,unused-argument,protected-access

PYLINT_TEST_FILE = Path(__file__).parent / 'data' / 'linter_test_file'


class MockAdmin:
    def register_plugin(self, name, administrator):
        pass


@pytest.fixture(scope='function')
def test_config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def test_object():
    return create_test_file_object()


@pytest.fixture(scope='function')
def stub_plugin(test_config, monkeypatch):
    monkeypatch.setattr('plugins.base.BasePlugin._sync_view', lambda self, plugin_path: None)
    return AnalysisPlugin(MockAdmin(), test_config, offline_testing=True)


@pytest.mark.parametrize('shebang_and_type', [
    (b'#!/usr/bin/env python3', b'testfile1:4 lines(4 sloc)\n  type:Text\n  mime type:text/plain\n  language:Python\n', 'python'),
    (b'#!/usr/bin/python', b'testfile1:4 lines(4 sloc)\n  type:Text\n  mime type:text/plain\n  language:Python\n', 'python'),
    (b'#!/bin/bash', b'testfile1:4 lines(4 sloc)\n  type:Text\n  mime type:text/plain\n  language:Shell\n', 'shell'),
    (b'#!/bin/sh', b'testfile1:4 lines(4 sloc)\n  type:Text\n  mime type:text/plain\n  language:Shell\n', 'shell')
])
def test_get_script_type_shebang(shebang_and_type, stub_plugin, test_object):
    shebang, output, script_type = shebang_and_type
    test_object.binary = shebang + b'\n' + test_object.binary
    assert stub_plugin._get_script_type(test_object, output.decode()) == script_type


def test_get_script_type_raises(stub_plugin, test_object):
    with pytest.raises(NotImplementedError):
        output = b'testfile1:3 lines(3 sloc)\n  type:Text\n  mime type:text/plain\n  language:\n'
        stub_plugin._get_script_type(test_object, output.decode())


def test_process_object_not_supported(stub_plugin, test_object):
    result = stub_plugin.process_object(test_object)
    assert result.processed_analysis[stub_plugin.NAME] == {'summary': [], 'warning': 'Unsupported script type'}


def test_process_object_this_file(stub_plugin):
    test_file = create_test_file_object(bin_path=str(PYLINT_TEST_FILE))
    stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert result['full']
    assert result['full'][0]['type'] == 'warning'
    assert result['full'][0]['symbol'] == 'unused-import'


def test_process_object_no_issues(stub_plugin, test_object, monkeypatch):
    test_object.processed_analysis['file_type'] = {'full': 'anything containing python'}
    monkeypatch.setattr('plugins.analysis.linter.code.source_code_analysis.python_linter.PythonLinter.do_analysis',
                        lambda self, file_path: list())
    stub_plugin.process_object(test_object)
    result = test_object.processed_analysis[stub_plugin.NAME]
    assert 'full' not in result


@pytest.fixture(scope='function')
def docker_timeout(monkeypatch):
    def run_timeout(*_, **__):
        raise ReadTimeout()
    monkeypatch.setattr('plugins.analysis.linter.code.source_code_analysis.run_docker_container', run_timeout)


def test_process_object_timeout(stub_plugin, test_object, docker_timeout):
    fo = stub_plugin.process_object(test_object)
    assert 'warning' in fo.processed_analysis[stub_plugin.NAME]
    assert fo.processed_analysis[stub_plugin.NAME]['warning'] == 'Analysis timed out'


@pytest.fixture(scope='function')
def docker_exception(monkeypatch):
    def run_exception(*_, **__):
        raise DockerException
    monkeypatch.setattr('plugins.analysis.linter.code.source_code_analysis.run_docker_container', run_exception)


def test_process_object_exception(stub_plugin, test_object, docker_exception):
    fo = stub_plugin.process_object(test_object)
    assert 'warning' in fo.processed_analysis[stub_plugin.NAME]
    assert fo.processed_analysis[stub_plugin.NAME]['warning'] == 'Error during analysis'
