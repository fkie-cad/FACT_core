from collections import namedtuple
from pathlib import Path

import pytest

from helperFunctions.config import get_config_for_testing
from helperFunctions.tag import TagColor
from objects.file import FileObject
from ..code.elf_analysis import AnalysisPlugin

TEST_DATA_DIR = Path(Path(__file__).parent, 'data')


class MockAdmin:
    def register_plugin(self, name, administrator):
        pass


LiefResult = namedtuple('LiefResult', ['symbols_version', 'libraries', 'imported_functions', 'exported_functions'])


@pytest.fixture(scope='function')
def test_config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def stub_object():
    test_object = FileObject(file_path=str(Path(TEST_DATA_DIR, 'test_binary')))
    test_object.processed_analysis['file_type'] = {'mime': 'application/x-executable'}

    return test_object


@pytest.fixture(scope='function')
def stub_plugin(test_config, monkeypatch):
    monkeypatch.setattr('plugins.base.BasePlugin._sync_view', lambda self, plugin_path: None)
    return AnalysisPlugin(MockAdmin(), test_config, offline_testing=True)


def test_process_analysis(stub_plugin, stub_object):
    stub_object.processed_analysis['file_type'] = {'mime': 'application/x-executable'}
    stub_plugin.process_object(stub_object)

    assert stub_object.processed_analysis[stub_plugin.NAME]['Output'] != {}
    result_summary = sorted(stub_object.processed_analysis[stub_plugin.NAME]['summary'])
    assert result_summary == ['dynamic_entries', 'exported_functions', 'header', 'imported_functions', 'libraries', 'sections', 'segments', 'symbols_version']


@pytest.mark.parametrize('tag, tag_color', [
    ('crypto', TagColor.RED),
    ('file_system', TagColor.BLUE),
    ('network', TagColor.ORANGE),
    ('memory_operations', TagColor.GREEN),
    ('randomize', TagColor.LIGHT_BLUE),
    ('other', TagColor.GRAY)])
def test_get_color_code(stub_plugin, tag, tag_color):
    assert stub_plugin._get_color_codes(tag) == tag_color


@pytest.mark.parametrize('indicators, behaviour_class, libraries, tags, expected', [
    (['a'], 'b', ['c'], [], []),
    (['a', 'b', 'c'], 'b', ['c'], [], ['b']),
    (['a', 'b', 'c'], 'b', ['c'], ['b'], ['b', 'b']),
    (['a', 'b', 'c'], 'b', ['c', 'a'], [], ['b', 'b']),
    (['a', 'b', 'c'], 'b', ['d', 'e'], [], []),
    (['a', 'b', 'c'], 'b', ['d', 'e'], ['x'], ['x'])
])
def test_get_tags_from_library_list(stub_plugin, indicators, behaviour_class, libraries, tags, expected):
    stub_plugin._get_tags_from_library_list(libraries, behaviour_class, indicators, tags)
    assert tags == expected


@pytest.mark.parametrize('functions, behaviour_class, indicators, tags, expected_result', [
    ([], '', [], [], []),
    (['a'], 'c', ['b'], [], []),
    (['a'], 'c', ['b'], ['d'], ['d']),
    (['a', 'b'], 'c', ['b'], ['d'], ['d', 'c']),
    (['a', 'b', 'x', 'y'], 'c', ['o', 'p', 'y'], [], ['c']),
    (['a', 'b'], 'c', ['b'], ['d', 'e'], ['d', 'e', 'c'])
])
def test_get_tags_from_function_list(stub_plugin, functions, behaviour_class, indicators, tags, expected_result):
    stub_plugin._get_tags_from_function_list(functions, behaviour_class, indicators, tags)
    assert tags == expected_result


def test_get_tags(stub_plugin, monkeypatch):
    behaviour_classes = {
        'one': ['x', 'y'],
        'two': ['z', 'a'],
        'three': ['f', 'u']
    }
    monkeypatch.setattr('plugins.analysis.elf_analysis.code.elf_analysis.AnalysisPlugin._load_template_file_as_json_obj', lambda _, __: behaviour_classes)
    tags = stub_plugin._get_tags(libraries=['a', 'b', 'c'], functions=['d', 'e', 'f'])
    assert sorted(tags) == ['three', 'two']


@pytest.mark.parametrize('symbol_versions, expected', [
    (['GLIBC_2.3.4(4)', '* Local *', 'GLIBC_2.2.5(3)', '* Global *', 'GLIBC_2.2.5(3)'],
     ['GLIBC_2.3.4', 'GLIBC_2.2.5'])

])
def test_get_symbols_version_entries(stub_plugin, symbol_versions, expected):
    assert sorted(stub_plugin._get_symbols_version_entries(symbol_versions)) == sorted(expected)


def test_create_tags(stub_plugin, stub_object):
    stub_object.processed_analysis[stub_plugin.NAME] = {}
    stub_result = LiefResult(libraries=['libz', 'unknown'], imported_functions=list(), symbols_version=list(), exported_functions=list())
    stub_plugin.create_tags(stub_result, stub_object)

    assert 'compression' in stub_object.processed_analysis[stub_plugin.NAME]['tags']


def test_analyze_elf_bad_file(stub_plugin, stub_object, tmpdir):
    random_file = Path(tmpdir, 'random')
    random_file.write_bytes(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    stub_object.file_path = str(random_file.absolute())

    result = stub_plugin._analyze_elf(stub_object)
    assert result == {}


final_analysis_test_data = [
    ({}, {}, 0),
    ({'header': [], 'segments': [1, 2], 'a': []}, {}, 1)
]


@pytest.mark.parametrize('binary_json_dict, elf_dict, expected', final_analysis_test_data)
def test_get_final_analysis_dict(stub_plugin, binary_json_dict, elf_dict, expected):
    stub_plugin.get_final_analysis_dict(binary_json_dict, elf_dict)
    assert len(elf_dict) == expected
