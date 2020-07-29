#!/usr/bin/env python3


from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.checksec import check_pie, check_relro, check_mitigations, check_nx_or_canary, check_fortify
from ..code.checksec import AnalysisPlugin


FILE_PATH = 'usr/test_dir/path'


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
        readelf = ''
        check_pie(FILE_PATH, resD, sumD, readelf)
        assert resD == {'PIE': 'invalid ELF file'}
        assert sumD == {'PIE - invalid ELF file': 'usr/test_dir/path'}

        resD, sumD = {}, {}
        readelf = '0xabcdefghi Type:      EXEC 0x0000000000'
        check_pie(FILE_PATH, resD, sumD, readelf)
        assert resD == {'PIE': 'disabled'}
        assert sumD == {'PIE disabled': 'usr/test_dir/path'}

        resD, sumD = {}, {}
        readelf = '0xabcdefghi Type:      DYN 0x000000000'
        check_pie(FILE_PATH, resD, sumD, readelf)
        assert resD == {'PIE': 'DSO'}
        assert sumD == {'PIE/DSO present': 'usr/test_dir/path'}

        resD, sumD = {}, {}
        readelf = '0xabcdefghi Type:      DYN 0x000000000 0xabcdefghi !?* (DEBUG)'
        check_pie(FILE_PATH, resD, sumD, readelf)
        assert resD == {'PIE': 'enabled'}
        assert sumD == {'PIE enabled': 'usr/test_dir/path'}

    def test_check_relro(self):
        resD, sumD = {}, {}
        readelf = ''
        check_relro(FILE_PATH, resD, sumD, readelf)
        assert resD == {'RELRO': 'disabled'}
        assert sumD == {'RELRO disabled': 'usr/test_dir/path'}

        resD, sumD = {}, {}
        readelf = '0xabcdefghi BIND_NOW 0x000000000 0xabcdefghi !?* GNU_RELRO'
        check_relro(FILE_PATH, resD, sumD, readelf)
        assert resD == {'RELRO': 'fully enabled'}
        assert sumD == {'RELRO fully enabled': 'usr/test_dir/path'}

        resD, sumD = {}, {}
        readelf = '0x000000000 0xabcdefghi !?* GNU_RELRO 0xabcdefghi'
        check_relro(FILE_PATH, resD, sumD, readelf)
        assert resD == {'RELRO': 'partially enabled'}
        assert sumD == {'RELRO partially enabled': 'usr/test_dir/path'}

    def test_check_nx(self):
        resD, sumD = {}, {}
        readelf = ''
        check_nx_or_canary(FILE_PATH, resD, sumD, readelf, 'NX')
        assert resD == {'NX': 'enabled'}
        assert sumD == {'NX enabled': 'usr/test_dir/path'}

        resD, sumD = {}, {}
        readelf = ' 0x000000000 0xabcdefghi !?* __stack_chk_fail GNU_STACK 0x00000054a 0xabcdefghijk 0x0000000000 RWE'
        check_nx_or_canary(FILE_PATH, resD, sumD, readelf, 'NX')
        assert resD == {'NX': 'disabled'}
        assert sumD == {'NX disabled': 'usr/test_dir/path'}

    def test_check_canary(self):
        resD, sumD = {}, {}
        readelf = ''
        check_nx_or_canary(FILE_PATH, resD, sumD, readelf, 'Canary')
        assert resD == {'Canary': 'disabled'}
        assert sumD == {'Canary disabled': 'usr/test_dir/path'}

        resD, sumD = {}, {}
        readelf = ' 0x000000000 0xabcdefghi !?* __stack_chk_fail GNU_STACK 0x00000054a 0xabcdefghijk 0x0000000000 RWE'
        check_nx_or_canary(FILE_PATH, resD, sumD, readelf, 'Canary')
        assert resD == {'Canary': 'enabled'}
        assert sumD == {'Canary enabled': 'usr/test_dir/path'}

    def test_canaries_and_no_fortify(self):
        resD, sumD = {}, {}
        readelf = ' 0x000000000 0xabcdefghi !?* __stack_chk_fail GNU_STACK 0x00000054a 0xabcdefghijk 0x0000000000 RWE'
        check_nx_or_canary(FILE_PATH, resD, sumD, readelf, 'Canary')
        check_fortify(FILE_PATH, resD, sumD, readelf)
        assert resD == {'Canary': 'enabled', 'FORTIFY_SOURCE': 'disabled'}
        assert sumD == {'Canary enabled': 'usr/test_dir/path', 'FORTIFY_SOURCE disabled': 'usr/test_dir/path'}

    def test_fortify_source(self):
        resD, sumD = {}, {}
        readelf = ' 00000021fc70  000500000007 R_X86_64_JUMP_SLO 0000000000000000 __snprintf_chk@GLIBC_2.3.4 + 0'
        check_fortify(FILE_PATH, resD, sumD, readelf)
        assert resD == {'FORTIFY_SOURCE': 'enabled'}
        assert sumD == {'FORTIFY_SOURCE enabled': 'usr/test_dir/path'}

        resD, sumD = {}, {}
        readelf = ' 00000021ff68  006900000007 R_X86_64_JUMP_SLO 0000000000000000 gethostname@GLIBC_2.2.5 + 0'
        check_fortify(FILE_PATH, resD, sumD, readelf)
        assert resD == {'FORTIFY_SOURCE': 'disabled'}
        assert sumD == {'FORTIFY_SOURCE disabled': 'usr/test_dir/path'}

    def test_check_mitigations(self):
        results = check_mitigations(FILE_PATH)
        assert 2 == len(results)
