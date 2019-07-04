import pytest
from helperFunctions.config import get_config_for_testing
from test.common_helper import create_test_file_object

from ..code.source_code_analysis import AnalysisPlugin


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


@pytest.mark.parametrize('mime_and_type', [
    ('Python script, ASCII text executable', 'python'),
    ('python3 script, ASCII text executable', 'python'),
    ('Bourne-Again shell script, UTF-8 Unicode text executable', 'shell')
])
def test_determine_script_type_file_type(mime_and_type, stub_plugin, test_object):
    mime, script_type = mime_and_type
    test_object.processed_analysis['file_type'] = {'full': mime}

    assert stub_plugin._determine_script_type(test_object) == script_type


@pytest.mark.parametrize('shebang_and_type', [
    (b'#!/usr/bin/env python3', 'python'),
    (b'#!/usr/bin/python', 'python'),
    (b'#!/bin/bash', 'shell'),
    (b'#!/bin/sh', 'shell')
])
def test_determine_script_type_shebang(shebang_and_type, stub_plugin, test_object):
    shebang, script_type = shebang_and_type
    test_object.binary = shebang + b'\n' + test_object.binary

    assert stub_plugin._determine_script_type(test_object) == script_type


@pytest.mark.parametrize('ending_and_type', [
    ('.py', 'python'),
    ('.sh', 'shell')
])
def test_determine_script_type_ending(ending_and_type, stub_plugin, test_object):
    ending, script_type = ending_and_type
    test_object.file_name = test_object.file_name + ending

    assert stub_plugin._determine_script_type(test_object) == script_type


def test_determine_script_type_raises(stub_plugin, test_object):
    with pytest.raises(NotImplementedError):
        stub_plugin._determine_script_type(test_object)


def test_process_object_not_supported(stub_plugin, test_object):
    result = stub_plugin.process_object(test_object)
    assert result.processed_analysis[stub_plugin.NAME] == {'summary': []}


def test_process_object_this_file(stub_plugin):
    test_file = create_test_file_object(bin_path=__file__)
    stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert result['full']
    assert result['full'][0]['type'] == 'warning'


def test_process_object_no_issues(stub_plugin, test_object, monkeypatch):
    test_object.processed_analysis['file_type'] = {'full': 'anything containing python'}
    monkeypatch.setattr('plugins.analysis.linter.code.source_code_analysis.python_linter.PythonLinter.do_analysis',
                        lambda self, file_path: list())
    stub_plugin.process_object(test_object)
    result = test_object.processed_analysis[stub_plugin.NAME]
    assert 'full' not in result
