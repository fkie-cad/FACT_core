from collections import namedtuple
from pathlib import Path

import pytest
from lief import Function

from analysis.plugin import Tag
from helperFunctions.tag import TagColor

from ..code.elf_analysis import (
    AnalysisPlugin,
    ElfHeader,
    _behaviour_class_applies,
    _get_behavior_classes,
    _get_symbols_version_entries,
)

TEST_DATA_DIR = Path(__file__).parent / 'data'

LiefResult = namedtuple(
    'LiefResult', ['symbols_version', 'libraries', 'imported_functions', 'exported_functions', 'sections']
)

MOCK_RESULT = AnalysisPlugin.Schema(
    header=ElfHeader(
        entrypoint=0,
        file_type='test',
        header_size=52,
        identity_abi_version=0,
        identity_class='CLASS32',
        identity_data='LSB',
        identity_os_abi='SYSTEMV',
        identity_version='',
        machine_type='',
        numberof_sections=1,
        numberof_segments=0,
        object_file_version='',
        processor_flag=0,
        program_header_size=0,
        program_headers_offset=0,
        section_header_size=0,
        section_headers_offset=0,
        section_name_table_idx=0,
    ),
    sections=[],
    segments=[],
    dynamic_entries=[],
    exported_functions=[],
    imported_functions=[],
    libraries=[],
    mod_info=None,
    note_sections=[],
    behavior_classes=['crypto', 'network'],
)


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestElfAnalysis:
    @pytest.mark.parametrize(
        ('tag', 'tag_color'),
        [
            ('crypto', TagColor.RED),
            ('file_system', TagColor.BLUE),
            ('network', TagColor.ORANGE),
            ('memory_operations', TagColor.GREEN),
            ('randomize', TagColor.LIGHT_BLUE),
            ('other', TagColor.GRAY),
        ],
    )
    def test_get_color_code(self, analysis_plugin, tag, tag_color):
        assert analysis_plugin._get_color_codes(tag) == tag_color

    @pytest.mark.parametrize(
        ('indicators', 'functions', 'libraries', 'should_apply'),
        [
            ([], [], [], False),
            (['foo'], [], ['test1234'], False),
            (['foo', 'test'], [], ['test1234'], True),  # for libraries, any substring match is OK
            (['foo'], ['test1234'], [], False),
            (['test'], ['test1234'], [], False),  # for function names, the coverage must be at least 85%
            (['foobar123'], ['foobar1234'], [], True),
        ],
    )
    def test_behaviour_class_applies(self, indicators, functions, libraries, should_apply):
        assert _behaviour_class_applies(functions, libraries, indicators) == should_apply

    def test_get_behavior_classes(self, analysis_plugin, monkeypatch):
        behaviour_classes = {'one': ['x', 'y'], 'two': ['z', 'a'], 'three': ['f', 'u']}
        monkeypatch.setattr('plugins.analysis.elf_analysis.code.elf_analysis.BEHAVIOUR_CLASSES', behaviour_classes)
        elf = LiefResult(
            libraries=['a', 'b', 'c'],
            imported_functions=[Function('d'), Function('e'), Function('f')],
            symbols_version=[],
            exported_functions=[],
            sections=[],
        )
        assert set(_get_behavior_classes(elf)) == {'three', 'two'}

    @pytest.mark.parametrize(
        ('symbol_versions', 'expected'),
        [
            (
                ['GLIBC_2.3.4(4)', '* Local *', 'GLIBC_2.2.5(3)', '* Global *', 'GLIBC_2.2.5(3)'],
                ['GLIBC_2.3.4', 'GLIBC_2.2.5'],
            )
        ],
    )
    def test_get_symbols_version_entries(self, analysis_plugin, symbol_versions, expected):
        assert sorted(_get_symbols_version_entries(symbol_versions)) == sorted(expected)

    def test_get_tags(self, analysis_plugin):
        tags = analysis_plugin.get_tags(MOCK_RESULT, [])
        assert len(tags) == 2
        assert Tag(name='crypto', value='crypto', color='danger', propagate=False) in tags

    def test_analyze_elf_bad_file(self, analysis_plugin, tmpdir):
        random_file = Path(tmpdir.dirname, 'random')
        random_file.write_bytes(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        with pytest.raises(ValueError, match='not a valid ELF file'), random_file.open('rb') as fp:
            analysis_plugin.analyze(fp, {}, {})

    def test_analyze_summarize(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'x-pie-executable'
        with test_file.open('rb') as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        assert result is not None
        assert result.header.machine_type == 'i386'
        assert len(result.sections) == 36
        assert result.sections[2].type == 'NOTE'
        assert len(result.segments) == 12
        assert result.segments[0].flags == ['read']
        assert result.behavior_classes == ['stringops', 'libc']
        assert any(f.name == 'puts' for f in result.imported_functions)

        summary = analysis_plugin.summarize(result)
        assert summary == ['sections', 'dynamic_entries', 'exported_functions', 'imported_functions', 'note_sections']

    def test_modinfo(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'test_data.ko'
        with test_file.open('rb') as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        assert result.mod_info == {'foo': 'bar', 'key': 'value'}
