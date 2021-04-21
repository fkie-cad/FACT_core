from pathlib import Path

import pytest

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.checksec import (
    AnalysisPlugin, check_canary, check_clang_cfi, check_clang_safestack, check_fortify_source, check_nx, check_pie,
    check_relro, check_rpath, check_runpath, check_stripped_symbols, execute_checksec_script
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

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_check_mitigations(self):
        test_file = FileObject(file_path=str(FILE_PATH_EXE))
        test_file.processed_analysis['file_type'] = {'full': 'ELF 64-bit LSB shared object, x86-64, dynamically linked'}
        self.analysis_plugin.process_object(test_file)
        result = test_file.processed_analysis[self.PLUGIN_NAME]

        assert result['NX'] == 'enabled'
        assert 'summary' in result
        assert 'NX enabled' in result['summary']


@pytest.mark.parametrize('file_path, check, expected_result, expected_summary', [
    (FILE_PATH_EXE, check_pie, {'PIE': 'enabled'}, {'PIE enabled': FILE_PATH_EXE}),
    (FILE_PATH_OBJECT, check_pie, {'PIE': 'REL'}, {'PIE/REL present': FILE_PATH_OBJECT}),
    (FILE_PATH_SHAREDLIB, check_pie, {'PIE': 'DSO'}, {'PIE/DSO present': FILE_PATH_SHAREDLIB}),
    (FILE_PATH_EXE_NO_PIE, check_pie, {'PIE': 'disabled'}, {'PIE disabled': FILE_PATH_EXE_NO_PIE}),
    # Test PIE: invalid ELF-File
    (FILE_PATH_EXE, check_relro, {'RELRO': 'fully enabled'}, {'RELRO fully enabled': FILE_PATH_EXE}),
    (FILE_PATH_OBJECT, check_relro, {'RELRO': 'disabled'}, {'RELRO disabled': FILE_PATH_OBJECT}),
    (FILE_PATH_SHAREDLIB, check_relro, {'RELRO': 'partially enabled'}, {'RELRO partially enabled': FILE_PATH_SHAREDLIB}),
])
def test_all_checks(file_path, check, expected_result, expected_summary):
    result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(file_path)
    check(file_path, result, dict_summary, dict_file_info)
    assert result == expected_result
    assert dict_summary == expected_summary


def test_check_nx():
    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE)
    check_nx(FILE_PATH_EXE, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'NX': 'enabled'}
    assert dict_summary == {'NX enabled': FILE_PATH_EXE}

    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_OBJECT)
    check_nx(FILE_PATH_OBJECT, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'NX': 'disabled'}
    assert dict_summary == {'NX disabled': FILE_PATH_OBJECT}


def test_check_canary():
    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE)
    check_canary(FILE_PATH_EXE, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'CANARY': 'disabled'}
    assert dict_summary == {'CANARY disabled': FILE_PATH_EXE}

    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE_CANARY)
    check_canary(FILE_PATH_EXE_CANARY, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'CANARY': 'enabled'}
    assert dict_summary == {'CANARY enabled': FILE_PATH_EXE_CANARY}


def test_check_fortify_source():
    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE)
    check_fortify_source(FILE_PATH_EXE, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'FORTIFY_SOURCE': 'disabled'}
    assert dict_summary == {'FORTIFY_SOURCE disabled': FILE_PATH_EXE}

    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE_FORTIFY)
    check_fortify_source(FILE_PATH_EXE_FORTIFY, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'FORTIFY_SOURCE': 'enabled'}
    assert dict_summary == {'FORTIFY_SOURCE enabled': FILE_PATH_EXE_FORTIFY}


def test_check_clang_cfi():
    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE)
    check_clang_cfi(FILE_PATH_EXE, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'CLANGCFI': 'disabled'}
    assert dict_summary == {'CLANGCFI disabled': FILE_PATH_EXE}

    # Test CLANCFI: enabled


def test_check_clang_safestack():
    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE)
    check_clang_safestack(FILE_PATH_EXE, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'SAFESTACK': 'disabled'}
    assert dict_summary == {'SAFESTACK disabled': FILE_PATH_EXE}

    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE_SAFESTACK)
    check_clang_safestack(FILE_PATH_EXE_SAFESTACK, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'SAFESTACK': 'enabled'}
    assert dict_summary == {'SAFESTACK enabled': FILE_PATH_EXE_SAFESTACK}


def test_check_rpath():
    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE)
    check_rpath(FILE_PATH_EXE, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'RPATH': 'disabled'}
    assert dict_summary == {'RPATH disabled': FILE_PATH_EXE}

    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE_RPATH)
    check_rpath(FILE_PATH_EXE_RPATH, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'RPATH': 'enabled'}
    assert dict_summary == {'RPATH enabled': FILE_PATH_EXE_RPATH}


def test_check_runpath():
    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE)
    check_runpath(FILE_PATH_EXE, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'RUNPATH': 'disabled'}
    assert dict_summary == {'RUNPATH disabled': FILE_PATH_EXE}

    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE_RUNPATH)
    check_runpath(FILE_PATH_EXE_RUNPATH, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'RUNPATH': 'enabled'}
    assert dict_summary == {'RUNPATH enabled': FILE_PATH_EXE_RUNPATH}


def test_check_stripped_symbols():
    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE)
    check_stripped_symbols(FILE_PATH_EXE, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'STRIPPED SYMBOLS': 'disabled'}
    assert dict_summary == {'STRIPPED SYMBOLS disabled': FILE_PATH_EXE}

    dict_result, dict_summary = {}, {}
    dict_file_info = execute_checksec_script(FILE_PATH_EXE_STRIPPED)
    check_stripped_symbols(FILE_PATH_EXE_STRIPPED, dict_result, dict_summary, dict_file_info)
    assert dict_result == {'STRIPPED SYMBOLS': 'enabled'}
    assert dict_summary == {'STRIPPED SYMBOLS enabled': FILE_PATH_EXE_STRIPPED}
