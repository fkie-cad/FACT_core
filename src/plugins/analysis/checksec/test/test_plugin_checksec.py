#!/usr/bin/env python3

from pathlib import Path
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.checksec import load_information, check_pie, check_relro, check_mitigations, check_nx, check_canary,\
     check_fortify_source, check_clang_CFI, check_clang_SafeStack, check_stripped_symbols_in_the_binary, check_rpath, check_runpath
from ..code.checksec import AnalysisPlugin


dir_checksec = Path(__file__).parent.parent
FILE_PATH_EXE = dir_checksec/'test/data/Hallo.out'
FILE_PATH_OBJECT = dir_checksec/'test/data/Hallo.o'
FILE_PATH_SHAREDLIB = dir_checksec/'test/data/Hallo.so'

FILE_PATH_EXE_CANARY = dir_checksec/'test/data/Hallo_Canary'
FILE_PATH_EXE_SAFESTACK = dir_checksec/'test/data/Hallo_SafeStack'
FILE_PATH_EXE_NO_PIE = dir_checksec/'test/data/Hallo_no_pie'
FILE_PATH_EXE_FORTIFY = dir_checksec/'test/data/Hallo_Fortify'
FILE_PATH_EXE_RUNPATH = dir_checksec/'test/data/Hallo_runpath'
FILE_PATH_EXE_RPATH = dir_checksec/'test/data/Hallo_rpath'
FILE_PATH_EXE_STRIPPED = dir_checksec/'test/data/Hallo_stripped'





class TestAnalysisPluginChecksec(AnalysisPluginTest):
    PLUGIN_NAME = 'exploit_mitigations'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()

    def test_check_pie(self):
        resD, sumD = {}, {}
        dict_file_info= load_information(FILE_PATH_EXE)
        check_pie(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'PIE': 'enabled'}
        assert sumD == {'PIE enabled': FILE_PATH_EXE}
        
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_OBJECT)
        check_pie(FILE_PATH_OBJECT, resD, sumD, dict_file_info)
        assert resD == {'PIE': 'REL'}
        assert sumD == {'PIE/REL present': FILE_PATH_OBJECT}
        
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_SHAREDLIB)
        check_pie(FILE_PATH_SHAREDLIB, resD, sumD, dict_file_info)
        assert resD == {'PIE': 'DSO'}
        assert sumD == {'PIE/DSO present': FILE_PATH_SHAREDLIB}

        resD, sumD = {}, {}
        dict_file_info= load_information(FILE_PATH_EXE_NO_PIE)
        check_pie(FILE_PATH_EXE_NO_PIE, resD, sumD, dict_file_info)
        assert resD == {'PIE': 'disabled'}
        assert sumD == {'PIE disabled': FILE_PATH_EXE_NO_PIE}

        #Test PIE: invalid ELF-File

    def test_check_relro(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_relro(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'RELRO': 'fully enabled'}
        assert sumD == {'RELRO fully enabled': FILE_PATH_EXE}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_OBJECT)
        check_relro(FILE_PATH_OBJECT, resD, sumD, dict_file_info)
        assert resD == {'RELRO': 'disabled'}
        assert sumD == {'RELRO disabled': FILE_PATH_OBJECT}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_SHAREDLIB)
        check_relro(FILE_PATH_SHAREDLIB, resD, sumD, dict_file_info)
        assert resD == {'RELRO': 'partially enabled'}
        assert sumD == {'RELRO partially enabled': FILE_PATH_SHAREDLIB}


    def test_check_nx(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_nx(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'NX': 'enabled'}
        assert sumD == {'NX enabled': FILE_PATH_EXE}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_OBJECT)
        check_nx(FILE_PATH_OBJECT, resD, sumD, dict_file_info)
        assert resD == {'NX': 'disabled'}
        assert sumD == {'NX disabled': FILE_PATH_OBJECT}


    def test_check_canary(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_canary(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'CANARY': 'disabled'}
        assert sumD == {'CANARY disabled': FILE_PATH_EXE}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE_CANARY)
        check_canary(FILE_PATH_EXE_CANARY, resD, sumD, dict_file_info)
        assert resD == {'CANARY': 'enabled'}
        assert sumD == {'CANARY enabled': FILE_PATH_EXE_CANARY}

    
    def test_check_fortify_source(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_fortify_source(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'FORTIFY_SOURCE': 'disabled'}
        assert sumD == {'FORTIFY_SOURCE disabled': FILE_PATH_EXE}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE_FORTIFY)
        check_fortify_source(FILE_PATH_EXE_FORTIFY, resD, sumD, dict_file_info)
        assert resD == {'FORTIFY_SOURCE': 'enabled'}
        assert sumD == {'FORTIFY_SOURCE enabled': FILE_PATH_EXE_FORTIFY}

    def test_check_clang_CFI(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_clang_CFI(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'CLANGCFI': 'disabled'}
        assert sumD == {'CLANGCFI disabled': FILE_PATH_EXE}

        #Test CLANCFI: enabled

    def test_check_clang_SafeStack(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_clang_SafeStack(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'SAFESTACK': 'disabled'}
        assert sumD == {'SAFESTACK disabled': FILE_PATH_EXE}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE_SAFESTACK)
        check_clang_SafeStack(FILE_PATH_EXE_SAFESTACK, resD, sumD, dict_file_info)
        assert resD == {'SAFESTACK': 'enabled'}
        assert sumD == {'SAFESTACK enabled': FILE_PATH_EXE_SAFESTACK}

    def test_check_rpath(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_rpath(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'RPATH': 'disabled'}
        assert sumD == {'RPATH disabled': FILE_PATH_EXE}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE_RPATH)
        check_rpath(FILE_PATH_EXE_RPATH, resD, sumD, dict_file_info)
        assert resD == {'RPATH': 'enabled'}
        assert sumD == {'RPATH enabled': FILE_PATH_EXE_RPATH}


    def test_check_runpath(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_runpath(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'RUNPATH': 'disabled'}
        assert sumD == {'RUNPATH disabled': FILE_PATH_EXE}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE_RUNPATH)
        check_runpath(FILE_PATH_EXE_RUNPATH, resD, sumD, dict_file_info)
        assert resD == {'RUNPATH': 'enabled'}
        assert sumD == {'RUNPATH enabled': FILE_PATH_EXE_RUNPATH}

    def test_check_stripped_symbols_in_the_binary(self):
        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE)
        check_stripped_symbols_in_the_binary(FILE_PATH_EXE, resD, sumD, dict_file_info)
        assert resD == {'STRIPPED SYMBOLS IN THE BINARY': 'disabled'}
        assert sumD == {'STRIPPED SYMBOLS IN THE BINARY disabled': FILE_PATH_EXE}

        resD, sumD = {}, {}
        dict_file_info = load_information(FILE_PATH_EXE_STRIPPED)
        check_stripped_symbols_in_the_binary(FILE_PATH_EXE_STRIPPED, resD, sumD, dict_file_info)
        assert resD == {'STRIPPED SYMBOLS IN THE BINARY': 'enabled'}
        assert sumD == {'STRIPPED SYMBOLS IN THE BINARY enabled': FILE_PATH_EXE_STRIPPED}

    def test_check_mitigations(self):
        results = check_mitigations(FILE_PATH_EXE)
        assert 2 == len(results)
