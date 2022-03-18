# pylint: disable=redefined-outer-name,protected-access,wrong-import-order
from collections import namedtuple
from pathlib import Path

import pytest

from helperFunctions.tag import TagColor
from objects.file import FileObject
from test.common_helper import get_test_data_dir

from ..code.elf_analysis import AnalysisPlugin

TEST_DATA = Path(get_test_data_dir(), 'test_data_file.bin')

TEST_DATA_DIR = Path(__file__).parent / 'data'


LiefResult = namedtuple(
    'LiefResult', ['symbols_version', 'libraries', 'imported_functions', 'exported_functions', 'sections']
)

MOCK_DATA = (
    '{"header": {"entrypoint": 109724, "file_type": "DYNAMIC", "header_size": 52, "identity_class": "CLASS32", "identity_data": "LSB", "identity_os_abi": "SYSTEMV"},'
    '"dynamic_entries": [{"library": "libdl.so.2", "tag": "NEEDED", "value": 1}, {"library": "libc.so.6", "tag": "NEEDED", "value": 137}, {"tag": "INIT", "value": 99064}],'
    '"sections": [{"alignment": 0, "entry_size": 0, "flags": [], "information": 0, "link": 0, "name": "", "offset": 0, "size": 0, "type": "NULL", "virtual_address": 0}],'
    '"segments": [{"alignment": 4, "file_offset": 2269, "flags": 4, "physical_address": 2269, "physical_size": 8, '
    '"sections": [".ARM.exidx"], "type": "ARM_EXIDX", "virtual_address": 2269, "virtual_size": 8}],'
    '"symbols_version": [{"value": 0}, {"symbol_version_auxiliary": "GLIBC_2.4", "value": 2}, {"symbol_version_auxiliary": "GLIBC_2.4", "value": 2}]}'
)

MOCK_LIEF_RESULT = LiefResult(
    libraries=['libdl.so.2', 'libc.so.6'],
    imported_functions=['fdopen', 'calloc', 'strstr', 'raise', 'gmtime_r', 'strcmp'],
    symbols_version=[],
    exported_functions=['SHA256_Transform', 'GENERAL_NAMES_free', 'i2d_RSAPrivateKey', 'd2i_OCSP_REQUEST'],
    sections=[],
)


@pytest.fixture(scope='function')
def stub_object():
    test_object = FileObject(file_path=str(TEST_DATA))
    test_object.processed_analysis['file_type'] = {'mime': 'application/x-executable'}
    return test_object


@pytest.fixture(scope='function')
def stub_plugin(monkeypatch):
    monkeypatch.setattr('plugins.base.BasePlugin._sync_view', lambda self, plugin_path: None)
    return AnalysisPlugin(offline_testing=True)


@pytest.mark.parametrize(
    'tag, tag_color',
    [
        ('crypto', TagColor.RED),
        ('file_system', TagColor.BLUE),
        ('network', TagColor.ORANGE),
        ('memory_operations', TagColor.GREEN),
        ('randomize', TagColor.LIGHT_BLUE),
        ('other', TagColor.GRAY),
    ],
)
def test_get_color_code(stub_plugin, tag, tag_color):
    assert stub_plugin._get_color_codes(tag) == tag_color


@pytest.mark.parametrize(
    'indicators, behaviour_class, libraries, tags, expected',
    [
        (['a'], 'b', ['c'], [], []),
        (['a', 'b', 'c'], 'b', ['c'], [], ['b']),
        (['a', 'b', 'c'], 'b', ['c'], ['b'], ['b', 'b']),
        (['a', 'b', 'c'], 'b', ['c', 'a'], [], ['b', 'b']),
        (['a', 'b', 'c'], 'b', ['d', 'e'], [], []),
        (['a', 'b', 'c'], 'b', ['d', 'e'], ['x'], ['x']),
    ],
)
def test_get_tags_from_library_list(stub_plugin, indicators, behaviour_class, libraries, tags, expected):
    stub_plugin._get_tags_from_library_list(libraries, behaviour_class, indicators, tags)
    assert tags == expected


@pytest.mark.parametrize(
    'functions, behaviour_class, indicators, tags, expected_result',
    [
        ([], '', [], [], []),
        (['a'], 'c', ['b'], [], []),
        (['a'], 'c', ['b'], ['d'], ['d']),
        (['a', 'b'], 'c', ['b'], ['d'], ['d', 'c']),
        (['a', 'b', 'x', 'y'], 'c', ['o', 'p', 'y'], [], ['c']),
        (['a', 'b'], 'c', ['b'], ['d', 'e'], ['d', 'e', 'c']),
    ],
)
def test_get_tags_from_function_list(stub_plugin, functions, behaviour_class, indicators, tags, expected_result):
    stub_plugin._get_tags_from_function_list(functions, behaviour_class, indicators, tags)
    assert tags == expected_result


def test_get_tags(stub_plugin, monkeypatch):
    behaviour_classes = {'one': ['x', 'y'], 'two': ['z', 'a'], 'three': ['f', 'u']}
    monkeypatch.setattr('plugins.analysis.elf_analysis.code.elf_analysis.BEHAVIOUR_CLASSES', behaviour_classes)
    tags = stub_plugin._get_tags(libraries=['a', 'b', 'c'], functions=['d', 'e', 'f'])
    assert sorted(tags) == ['three', 'two']


@pytest.mark.parametrize(
    'symbol_versions, expected',
    [
        (
            ['GLIBC_2.3.4(4)', '* Local *', 'GLIBC_2.2.5(3)', '* Global *', 'GLIBC_2.2.5(3)'],
            ['GLIBC_2.3.4', 'GLIBC_2.2.5'],
        )
    ],
)
def test_get_symbols_version_entries(stub_plugin, symbol_versions, expected):
    assert sorted(stub_plugin._get_symbols_version_entries(symbol_versions)) == sorted(expected)


def test_create_tags(stub_plugin, stub_object):
    stub_object.processed_analysis[stub_plugin.NAME] = {}
    stub_result = LiefResult(
        libraries=['recvmsg', 'unknown'], imported_functions=[], symbols_version=[], exported_functions=[], sections=[]
    )
    stub_plugin.create_tags(stub_result, stub_object)

    assert 'network' in stub_object.processed_analysis[stub_plugin.NAME]['tags']
    assert stub_object.processed_analysis[stub_plugin.NAME]['tags']['network']['color'] == 'warning'


def test_analyze_elf_bad_file(stub_plugin, stub_object, tmpdir):
    random_file = Path(tmpdir.dirname, 'random')
    random_file.write_bytes(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    stub_object.file_path = str(random_file.absolute())

    result = stub_plugin._analyze_elf(stub_object)
    assert result == {}


final_analysis_test_data = [({}, {}, 0), ({'header': [], 'segments': [1, 2], 'a': []}, {}, 1)]


@pytest.mark.parametrize('binary_json_dict, elf_dict, expected', final_analysis_test_data)
def test_get_final_analysis_dict(stub_plugin, binary_json_dict, elf_dict, expected):
    stub_plugin.get_final_analysis_dict(binary_json_dict, elf_dict)
    assert len(elf_dict) == expected


def test_pie(stub_plugin):
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'x-pie-executable'))
    elf_dict, _ = stub_plugin._analyze_elf(test_file)
    assert elf_dict != {}


def test_plugin(stub_plugin, stub_object, monkeypatch):
    monkeypatch.setattr('lief.parse', lambda _: MOCK_LIEF_RESULT)
    monkeypatch.setattr('lief.to_json', lambda _: MOCK_DATA)

    stub_object.processed_analysis['file_type'] = {'mime': 'application/x-executable'}
    stub_plugin.process_object(stub_object)

    output = stub_object.processed_analysis[stub_plugin.NAME]['Output']
    assert output != {}
    result_summary = sorted(stub_object.processed_analysis[stub_plugin.NAME]['summary'])
    assert result_summary == [
        'dynamic_entries',
        'exported_functions',
        'header',
        'imported_functions',
        'libraries',
        'sections',
        'segments',
        'symbols_version',
    ]
    assert 'strcmp' in output['imported_functions']
    assert output['segments'][0]['virtual_address'].startswith('0x'), 'addresses should be converted to hex'


def test_modinfo(stub_plugin):
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'test_data.ko'))
    _, binary = stub_plugin._analyze_elf(test_file)
    result = stub_plugin.filter_modinfo(binary)
    assert result[0] == 'this are test data\n'
