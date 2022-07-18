from copy import deepcopy
from pathlib import Path

from test.common_helper import TEST_FW, CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest

VIEW = Path(__file__).parent.parent / 'view' / 'cpu_architecture.html'
ARCH_DETECTION_RESULT = {'MIPS (M)': 'Detection based on meta data'}


class DbMock(CommonDatabaseMock):

    def get_object(self, uid, analysis_filter=None):
        if uid == TEST_FW.uid:
            result = deepcopy(TEST_FW)
            result.processed_analysis = {'cpu_architecture': ARCH_DETECTION_RESULT}
            return result
        return None

    @staticmethod
    def get_view(_):
        return VIEW.read_bytes()


class TestCodescannerView(WebInterfaceTest):
    PLUGIN_NAME = 'cpu_architecture'

    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_view(self):
        result = self.test_client.get(f'/analysis/{TEST_FW.uid}/{self.PLUGIN_NAME}').data.decode()
        assert result != ''
        for key in ['Architecture', 'Means of Detection', 'MIPS (M)', 'Detection based on meta data']:
            assert key in result
