from copy import deepcopy
from pathlib import Path

import pytest

from conftest import CommonIntercomMock
from plugins.analysis.cpu_architecture.code.cpu_architecture import AnalysisPlugin, Architecture
from test.common_helper import TEST_FW, CommonDatabaseMock, generate_analysis_entry

PLUGIN_NAME = 'cpu_architecture'
VIEW = Path(__file__).parent.parent / 'view' / f'{PLUGIN_NAME}.html'
TEST_RESULT = AnalysisPlugin.Schema(
    architectures=[
        Architecture(value='MIPS (M)', detection_method='Detection based on meta data'),
    ]
)


class DbMock(CommonDatabaseMock):
    def get_object(self, uid, analysis_filter=None):
        if uid == TEST_FW.uid:
            result = deepcopy(TEST_FW)
            result.processed_analysis = {
                PLUGIN_NAME: generate_analysis_entry(
                    plugin_version='0.1.0',
                    analysis_result=TEST_RESULT.model_dump(),
                )
            }
            return result
        return None

    @staticmethod
    def get_view(_):
        return VIEW.read_bytes()


class IntercomMock(CommonIntercomMock):
    def get_available_analysis_plugins(self):
        return {
            **super().get_available_analysis_plugins(),
            PLUGIN_NAME: (f'{PLUGIN_NAME} plugin', False, {'default': False}, *self._common_fields),
        }


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock, intercom_mock_class=IntercomMock)
def test_cpu_architecture_view(test_client):
    result = test_client.get(f'/analysis/{TEST_FW.uid}/{PLUGIN_NAME}').data.decode()
    assert result != ''
    for key in [
        'Architecture',
        'Means of Detection',
        TEST_RESULT.architectures[0].value,
        TEST_RESULT.architectures[0].detection_method,
    ]:
        assert key in result
