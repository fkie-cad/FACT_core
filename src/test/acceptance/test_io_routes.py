import pytest

from helperFunctions import magic
from storage.db_interface_comparison import ComparisonDbInterface
from test.common_helper import create_test_firmware

COMPARISON_RESULT = {
    'general': {'a': {'id1': '<empty>', 'id2': '<empty>'}, 'b': {'id1': '<empty>', 'id2': '<empty>'}},
    'plugins': {'Ida_Diff_Highlighting': {'idb_binary': 'The IDA database'}},
}


def throwing_function(binary):  # noqa: ARG001
    raise Exception('I take exception to everything')


@pytest.fixture(autouse=True)
def _autouse_intercom_backend_binding(intercom_backend_binding):  # noqa: ARG001
    pass


class TestAcceptanceIoRoutes:
    test_fw = create_test_firmware(device_name='test_fw')

    def test_radare_button(self, test_client, backend_db):
        response = test_client.get(f'/radare-view/{self.test_fw.uid}')
        assert '200' in response.status, 'radare view link failed'
        assert b'File not found in database' in response.data, 'radare view should fail on missing uid'

        backend_db.add_object(self.test_fw)

        response = test_client.get(f'/radare-view/{self.test_fw.uid}')
        assert '200' in response.status, 'radare view link failed'
        assert b'with url: /v1/retrieve' in response.data, 'error coming from wrong request'
        assert b'Failed to establish a new connection' in response.data, 'connection shall fail'

    def test_ida_download(self, backend_db, test_client):
        comparison_interface = ComparisonDbInterface()

        backend_db.add_object(self.test_fw)

        COMPARISON_RESULT['general'] = {'a': {self.test_fw.uid: 'x'}, 'b': {self.test_fw.uid: 'y'}}

        comparison_interface.add_comparison_result(COMPARISON_RESULT)
        cid = comparison_interface._calculate_comp_id(COMPARISON_RESULT)

        response = test_client.get(f'/ida-download/{cid}')
        assert b'IDA database' in response.data, 'mocked ida database not in result'

    def test_ida_download_bad_uid(self, test_client):
        comparison_interface = ComparisonDbInterface()

        comparison_interface.add_comparison_result(COMPARISON_RESULT)
        cid = comparison_interface._calculate_comp_id(COMPARISON_RESULT)

        response = test_client.get(f'/ida-download/{cid}')
        assert b'not found' in response.data, 'endpoint should dismiss result'

    def test_pdf_download(self, test_client, backend_db):
        response = test_client.get(f'/pdf-download/{self.test_fw.uid}')
        assert response.status_code == 200, 'pdf download link failed'
        assert b'File not found in database' in response.data, 'radare view should fail on missing uid'

        backend_db.add_object(self.test_fw)

        response = test_client.get(f'/pdf-download/{self.test_fw.uid}')

        assert response.status_code == 200, 'pdf download failed'
        device = self.test_fw.device_name.replace(' ', '_')
        assert response.headers['Content-Disposition'] == f'attachment; filename={device}_analysis_report.pdf'
        assert magic.from_buffer(response.data, mime=True) == 'application/pdf'
