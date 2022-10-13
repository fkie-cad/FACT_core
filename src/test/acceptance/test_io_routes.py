from fact_helper_file import get_file_type_from_binary

from storage.db_interface_backend import BackendDbInterface
from storage.db_interface_comparison import ComparisonDbInterface
from test.acceptance.base import TestAcceptanceBase  # pylint: disable=wrong-import-order
from test.common_helper import create_test_firmware  # pylint: disable=wrong-import-order

COMPARE_RESULT = {
    'general': {
        'a': {'id1': '<empty>', 'id2': '<empty>'},
        'b': {'id1': '<empty>', 'id2': '<empty>'}
    },
    'plugins': {
        'Ida_Diff_Highlighting': {
            'idb_binary': 'The IDA database'
        }
    }
}


def throwing_function(binary):
    raise Exception('I take exception to everything')


class TestAcceptanceIoRoutes(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend_interface = BackendDbInterface(self.config)
        self.test_fw = create_test_firmware(device_name='test_fw')

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def test_radare_button(self):
        response = self.test_client.get(f'/radare-view/{self.test_fw.uid}')
        self.assertIn('200', response.status, 'radare view link failed')
        self.assertIn(b'File not found in database', response.data, 'radare view should fail on missing uid')

        self.db_backend_interface.add_object(self.test_fw)

        response = self.test_client.get(f'/radare-view/{self.test_fw.uid}')
        self.assertIn('200', response.status, 'radare view link failed')
        self.assertIn(b'with url: /v1/retrieve', response.data, 'error coming from wrong request')
        self.assertIn(b'Failed to establish a new connection', response.data, 'connection shall fail')

    def test_ida_download(self):
        compare_interface = ComparisonDbInterface(config=self.config)

        self.db_backend_interface.add_object(self.test_fw)

        COMPARE_RESULT['general'] = {'a': {self.test_fw.uid: 'x'}, 'b': {self.test_fw.uid: 'y'}}

        compare_interface.add_comparison_result(COMPARE_RESULT)
        cid = compare_interface._calculate_comp_id(COMPARE_RESULT)  # pylint: disable=protected-access

        response = self.test_client.get(f'/ida-download/{cid}')
        self.assertIn(b'IDA database', response.data, 'mocked ida database not in result')

    def test_ida_download_bad_uid(self):
        compare_interface = ComparisonDbInterface(config=self.config)

        compare_interface.add_comparison_result(COMPARE_RESULT)
        cid = compare_interface._calculate_comp_id(COMPARE_RESULT)  # pylint: disable=protected-access

        response = self.test_client.get(f'/ida-download/{cid}')
        self.assertIn(b'not found', response.data, 'endpoint should dismiss result')

    def test_pdf_download(self):
        response = self.test_client.get(f'/pdf-download/{self.test_fw.uid}')
        assert response.status_code == 200, 'pdf download link failed'
        assert b'File not found in database' in response.data, 'radare view should fail on missing uid'

        self.db_backend_interface.add_object(self.test_fw)

        response = self.test_client.get(f'/pdf-download/{self.test_fw.uid}')

        assert response.status_code == 200, 'pdf download failed'
        device = self.test_fw.device_name.replace(' ', '_')
        assert response.headers['Content-Disposition'] == f'attachment; filename={device}_analysis_report.pdf'
        assert get_file_type_from_binary(response.data)['mime'] == 'application/pdf'
