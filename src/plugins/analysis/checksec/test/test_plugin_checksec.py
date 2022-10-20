from pathlib import Path

import pytest

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.checksec import (
    AnalysisPlugin,
    check_canary,
    check_clang_cfi,
    check_clang_safestack,
    check_fortify_source,
    check_nx,
    check_pie,
    check_relro,
    check_rpath,
    check_runpath,
    check_stripped_symbols,
    execute_checksec_script,
)

PLUGIN_DIR = Path(__file__).parent.parent
FILE_PATH_EXE = PLUGIN_DIR / 'test/data/Hallo.out'
FILE_PATH_OBJECT = PLUGIN_DIR / 'test/data/Hallo.o'
FILE_PATH_SHAREDLIB = PLUGIN_DIR / 'test/data/Hallo.so'

FILE_PATH_EXE_CANARY = PLUGIN_DIR / 'test/data/Hallo_Canary'
FILE_PATH_EXE_SAFESTACK = PLUGIN_DIR / 'test/data/Hallo_SafeStack'
FILE_PATH_EXE_NO_PIE = PLUGIN_DIR / 'test/data/Hallo_no_pie'
FILE_PATH_EXE_FORTIFY = PLUGIN_DIR / 'test/data/Hallo_Fortify'
FILE_PATH_EXE_RUNPATH = PLUGIN_DIR / 'test/data/Hallo_runpath'
FILE_PATH_EXE_RPATH = PLUGIN_DIR / 'test/data/Hallo_rpath'
FILE_PATH_EXE_STRIPPED = PLUGIN_DIR / 'test/data/Hallo_stripped'


class TestAnalysisPluginChecksec(AnalysisPluginTest):

    PLUGIN_NAME = 'exploit_mitigations'
    PLUGIN_CLASS = AnalysisPlugin

    def test_check_mitigations(self):
        test_file = FileObject(file_path=str(FILE_PATH_EXE))
        test_file.processed_analysis['file_type'] = {'full': 'ELF 64-bit LSB shared object, x86-64, dynamically linked'}
        self.analysis_plugin.process_object(test_file)
        result = test_file.processed_analysis[self.PLUGIN_NAME]

        assert result['NX'] == 'enabled'
        assert 'summary' in result
        assert 'NX enabled' in result['summary']


@pytest.mark.parametrize(
    'file_path, check, expected_result, expected_summary',
    [
        (FILE_PATH_EXE, check_pie, {'PIE': 'enabled'}, 'PIE enabled'),
        (FILE_PATH_OBJECT, check_pie, {'PIE': 'REL'}, 'PIE/REL present'),
        (FILE_PATH_SHAREDLIB, check_pie, {'PIE': 'DSO'}, 'PIE/DSO present'),
        (FILE_PATH_EXE_NO_PIE, check_pie, {'PIE': 'disabled'}, 'PIE disabled'),
        # TODO: Test PIE: invalid ELF-File
        (FILE_PATH_EXE, check_relro, {'RELRO': 'fully enabled'}, 'RELRO fully enabled'),
        (FILE_PATH_OBJECT, check_relro, {'RELRO': 'disabled'}, 'RELRO disabled'),
        (FILE_PATH_SHAREDLIB, check_relro, {'RELRO': 'partially enabled'}, 'RELRO partially enabled'),
        (FILE_PATH_EXE, check_nx, {'NX': 'enabled'}, 'NX enabled'),
        (FILE_PATH_OBJECT, check_nx, {'NX': 'disabled'}, 'NX disabled'),
        (FILE_PATH_EXE, check_canary, {'CANARY': 'disabled'}, 'CANARY disabled'),
        (FILE_PATH_EXE_CANARY, check_canary, {'CANARY': 'enabled'}, 'CANARY enabled'),
        (FILE_PATH_EXE, check_fortify_source, {'FORTIFY_SOURCE': 'disabled'}, 'FORTIFY_SOURCE disabled'),
        (FILE_PATH_EXE_FORTIFY, check_fortify_source, {'FORTIFY_SOURCE': 'enabled'}, 'FORTIFY_SOURCE enabled'),
        (FILE_PATH_EXE, check_clang_cfi, {'CLANGCFI': 'disabled'}, 'CLANGCFI disabled'),
        # TODO: Test CLANCFI: enabled
        (FILE_PATH_EXE, check_clang_safestack, {'SAFESTACK': 'disabled'}, 'SAFESTACK disabled'),
        (FILE_PATH_EXE_SAFESTACK, check_clang_safestack, {'SAFESTACK': 'enabled'}, 'SAFESTACK enabled'),
        (FILE_PATH_EXE, check_rpath, {'RPATH': 'disabled'}, 'RPATH disabled'),
        (FILE_PATH_EXE_RPATH, check_rpath, {'RPATH': 'enabled'}, 'RPATH enabled'),
        (FILE_PATH_EXE, check_runpath, {'RUNPATH': 'disabled'}, 'RUNPATH disabled'),
        (FILE_PATH_EXE_RUNPATH, check_runpath, {'RUNPATH': 'enabled'}, 'RUNPATH enabled'),
        (FILE_PATH_EXE, check_stripped_symbols, {'STRIPPED SYMBOLS': 'disabled'}, 'STRIPPED SYMBOLS disabled'),
        (FILE_PATH_EXE_STRIPPED, check_stripped_symbols, {'STRIPPED SYMBOLS': 'enabled'}, 'STRIPPED SYMBOLS enabled'),
    ],
)
def test_all_checks(file_path, check, expected_result, expected_summary):
    result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(file_path)
    check(file_path, result, dict_summary, dict_file_info)
    assert result == expected_result
    assert dict_summary == {expected_summary: file_path}
