import os

import pytest
from common_helper_files import get_dir_of_file

from test.common_helper import MockFileObject

from ..code.hash import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')  # noqa: PTH118


@pytest.mark.backend_config_overwrite(
    {
        'plugin': {
            'file_hashes': {
                'name': 'file_hashes',
                'hashes': ['md5', 'sha1', 'foo'],
            },
        }
    },
)
@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginHash:
    def test_all_hashes(self, analysis_plugin):
        result = analysis_plugin.process_object(MockFileObject()).processed_analysis[analysis_plugin.NAME]

        assert 'md5' in result, 'md5 not in result'
        assert 'sha1' in result, 'sha1 not in result'
        assert 'foo' not in result, 'foo in result but not available'
        assert result['md5'] == '6f8db599de986fab7a21625b7916589c', 'hash not correct'
        assert 'ssdeep' in result, 'ssdeep not in result'
        assert 'imphash' in result, 'imphash not in result'

    def test_imphash(self, analysis_plugin):
        file_path = os.path.join(TEST_DATA_DIR, 'ls')  # noqa: PTH118
        result = analysis_plugin.process_object(MockFileObject(file_path=file_path)).processed_analysis[
            analysis_plugin.NAME
        ]

        assert isinstance(result['imphash'], str), 'imphash should be a string'
        assert len(result['imphash']) == 32, 'imphash does not look like an md5'  # noqa: PLR2004
