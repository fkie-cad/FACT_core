from io import FileIO
from pathlib import Path

import pytest

from ..code.uefi import AnalysisPlugin, Schema
from plugins.analysis.file_type.code.file_type import AnalysisPlugin as FileType

TEST_FILE = Path(__file__).parent / 'data' / 'test_file.pe'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestFileSystemMetadata:
    def test_analyze_summarize_and_tag(self, analysis_plugin):
        assert TEST_FILE.is_file(), 'test file is missing'
        dependencies = {
            'file_type': FileType.Schema(
                mime='application/x-dosexec',
                full='MS-DOS executable PE32+ executable (DLL) (EFI boot service driver) x86-64, for MS Windows',
            )
        }
        result = analysis_plugin.analyze(FileIO(str(TEST_FILE)), {}, dependencies)
        assert isinstance(result, Schema)
        assert len(result.vulnerabilities) > 0

        rules_by_name = {r.name: r for r in result.vulnerabilities}
        assert 'BRLY-2021-007' in rules_by_name
        matching_rule = rules_by_name['BRLY-2021-007']
        assert matching_rule.variants[0].match is True, 'rule did not match'

        summary = analysis_plugin.summarize(result)
        assert summary == [matching_rule.category]

        tags = analysis_plugin.get_tags(result, summary)
        assert len(tags) == 1
        assert tags[0].name == matching_rule.category
