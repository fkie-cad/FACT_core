from io import FileIO
from pathlib import Path

import yara

from fact.analysis.plugin.addons import Yara
from fact.analysis.plugin.compat import yara_match_to_dict
from fact.analysis.YaraPluginBase import YaraBasePlugin
from fact.helperFunctions.fileSystem import get_src_dir
from fact.test.common_helper import create_test_file_object

signature_file = str(Path(get_src_dir()) / 'test/unit/analysis/test.yara')
test_target = str(Path(get_src_dir()) / 'test/data/files/get_files_test/testfile1')

EXPECTED_RESULT = {
    'matches': True,
    'meta': {
        'description': 'Generic Software',
        'open_source': False,
        'software_name': 'Test Software',
        'website': 'http://www.fkie.fraunhofer.de',
    },
    'rule': 'testRule',
    'strings': [(0, '$a', 'test'), (22, '$a', 'Test')],
}


class MockYaraPlugin(YaraBasePlugin):
    def __init__(self):
        self.signature_path = signature_file
        self.NAME = 'test_plugin'


class MockYaraAddonPlugin(Yara):
    def __init__(self):
        self._rules = yara.compile(signature_file)


def test_output_is_compatible():
    fo = create_test_file_object(test_target)
    plugin = MockYaraPlugin()
    plugin.process_object(fo)
    assert fo.processed_analysis['test_plugin']['testRule'] == EXPECTED_RESULT

    yara_addon_plugin = MockYaraAddonPlugin()
    file = FileIO(test_target)
    yara_matches = yara_addon_plugin.match(file)
    assert all(isinstance(m, yara.Match) for m in yara_matches)
    converted_match = yara_match_to_dict(yara_matches[0])
    assert converted_match['strings'] == EXPECTED_RESULT['strings']
    for key, value in EXPECTED_RESULT['meta'].items():
        assert converted_match['meta'][key] == value
