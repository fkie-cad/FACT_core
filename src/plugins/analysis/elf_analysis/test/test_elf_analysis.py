import os
from collections import namedtuple
from pathlib import Path
from unittest.mock import patch
import json
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from objects.file import FileObject

from ..code.elf_analysis import AnalysisPlugin


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

MOCK_DATA = json.dumps({'header': {'entrypoint': 109724, 'file_type': 'DYNAMIC', 'header_size': 52, 'identity_class': 'CLASS32', 'identity_data': 'LSB', 'identity_os_abi': 'SYSTEMV', 'identity_version': 'CURRENT', 'machine_type': 'ARM', 'numberof_sections': 31, 'object_file_version': 'CURRENT', 'processor_flag': 83886592, 'processornumberof_segments_flag': 9, 'program_header_size': 32, 'program_headers_offset': 52, 'section_header_size': 40, 'section_headers_offset': 2778884, 'section_name_table_idx': 30},
                        'dynamic_entries': [{'library': 'libdl.so.2', 'tag': 'NEEDED', 'value': 1}, {'library': 'libc.so.6', 'tag': 'NEEDED', 'value': 137}, {'tag': 'INIT', 'value': 99064}, {'tag': 'FINI', 'value': 1967508}, {'array': [110108], 'tag': 'INIT_ARRAY', 'value': 2337064}, {'tag': 'INIT_ARRAYSZ', 'value': 4}, {'array': [110004], 'tag': 'FINI_ARRAY', 'value': 2337068}],
                        'sections': [{'alignment': 0, 'entry_size': 0, 'flags': [], 'information': 0, 'link': 0, 'name': '', 'offset': 0, 'size': 0, 'type': 'NULL', 'virtual_address': 0}, {'alignment': 1, 'entry_size': 0, 'flags': ['ALLOC'], 'information': 0, 'link': 0, 'name': '.interp', 'offset': 340, 'size': 19, 'type': 'PROGBITS', 'virtual_address': 340}],
                        'segments': [{'alignment': 4, 'file_offset': 2269500, 'flags': 4, 'physical_address': 2269500, 'physical_size': 8, 'sections': ['.ARM.exidx'], 'type': 'ARM_EXIDX', 'virtual_address': 2269500, 'virtual_size': 8}, {'alignment': 4, 'file_offset': 52, 'flags': 5, 'physical_address': 52, 'physical_size': 288, 'sections': [], 'type': 'PHDR', 'virtual_address': 52, 'virtual_size': 288}],
                        'symbols_version': [{'value': 0}, {'value': 0}, {'symbol_version_auxiliary': 'GLIBC_2.4', 'value': 2}, {'symbol_version_auxiliary': 'GLIBC_2.4', 'value': 2}, {'symbol_version_auxiliary': 'GLIBC_2.4', 'value': 2}]})

LiefResult = namedtuple('LiefResult', ['symbols_version', 'libraries', 'imported_functions', 'exported_functions'])


class TestAnalysisPluginElfAnalysis(AnalysisPluginTest):

    PLUGIN_NAME = 'elf_analysis'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        # additional config can go here
        # additional setup can go here
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()
        # additional tearDown can go here

    @patch('lief.parse', lambda x: LiefResult(libraries=['libdl.so.2', 'libc.so.6'],
                                              imported_functions=['fdopen', 'calloc', 'strstr', 'raise', 'gmtime_r', 'strcmp'],
                                              symbols_version=list(),
                                              exported_functions=['SHA256_Transform', 'GENERAL_NAMES_free', 'i2d_RSAPrivateKey', 'd2i_OCSP_REQUEST', 'i2d_OCSP_REQUEST', 'i2d_OCSP_RESPONSE', 'd2i_X509_CRL', 'EC_KEY_new', 'd2i_PUBKEY']))
    @patch('lief.to_json_from_abstract', lambda x: MOCK_DATA)
    def test_plugin(self):
        test_object = FileObject(file_path=str(Path(TEST_DATA_DIR) / 'test_binary'))
        test_object.processed_analysis['file_type'] = {'mime': 'application/x-executable'}
        self.analysis_plugin.process_object(test_object)

        self.assertNotEqual(test_object.processed_analysis[self.PLUGIN_NAME]['Output'], {})
        self.assertEqual(sorted(test_object.processed_analysis[self.PLUGIN_NAME]['summary']), ['dynamic_entries',
                                                                                               'exported_functions', 'header',
                                                                                               'imported_functions', 'libraries',
                                                                                               'sections', 'segments', 'symbols_version'])
