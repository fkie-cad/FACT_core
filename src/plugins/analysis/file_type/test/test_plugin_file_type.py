import io

import pytest

from test.common_helper import get_test_data_dir

from ..code.file_type import AnalysisPlugin


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_detect_type_of_file(analysis_plugin):
    result = analysis_plugin.analyze(
        io.FileIO(f'{get_test_data_dir()}/container/test.zip'),
        {},
        {},
    )
    summary = analysis_plugin.summarize(result)

    assert result.mime == 'application/zip', 'mime-type not detected correctly'
    assert result.full.startswith('Zip archive data,'), 'full type not correct'

    assert summary == ['application/zip']
