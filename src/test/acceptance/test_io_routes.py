# pylint: disable=no-self-use
import pytest
from fact_helper_file import get_file_type_from_binary

from storage.db_interface_comparison import ComparisonDbInterface
from test.common_helper import create_test_firmware

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

test_fw = create_test_firmware(device_name='test_fw')


@pytest.fixture
def compare_interface(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    yield ComparisonDbInterface(config=configparser_cfg)


@pytest.mark.usefixtures('backend_services')
class TestAcceptanceIoRoutes:
    def test_radare_button(self, test_client, backend_services):
        response = test_client.get(f'/radare-view/{test_fw.uid}')
        assert '200' in response.status, 'radare view link failed'
        assert b'File not found in database' in response.data, 'radare view should fail on missing uid'

        backend_services.db_backend_interface.add_object(test_fw)

        response = test_client.get(f'/radare-view/{test_fw.uid}')
        assert '200' in response.status, 'radare view link failed'
        assert b'with url: /v1/retrieve' in response.data, 'error coming from wrong request'
        assert b'Failed to establish a new connection' in response.data, 'connection shall fail'

    def test_ida_download(self, test_client, backend_services, compare_interface):
        backend_services.db_backend_interface.add_object(test_fw)

        COMPARE_RESULT['general'] = {'a': {test_fw.uid: 'x'}, 'b': {test_fw.uid: 'y'}}

        compare_interface.add_comparison_result(COMPARE_RESULT)
        cid = compare_interface._calculate_comp_id(COMPARE_RESULT)  # pylint: disable=protected-access

        response = test_client.get(f'/ida-download/{cid}')
        assert b'IDA database' in response.data, 'mocked ida database not in result'

    def test_ida_download_bad_uid(self, test_client, compare_interface):
        compare_interface.add_comparison_result(COMPARE_RESULT)
        cid = compare_interface._calculate_comp_id(COMPARE_RESULT)  # pylint: disable=protected-access

        response = test_client.get(f'/ida-download/{cid}')
        assert b'not found' in response.data, 'endpoint should dismiss result'

    def test_pdf_download(self, test_client, backend_services):
        response = test_client.get(f'/pdf-download/{test_fw.uid}')
        assert response.status_code == 200, 'pdf download link failed'
        assert b'File not found in database' in response.data, 'radare view should fail on missing uid'

        backend_services.db_backend_interface.add_object(test_fw)

        response = test_client.get(f'/pdf-download/{test_fw.uid}')

        assert response.status_code == 200, 'pdf download failed'
        device = test_fw.device_name.replace(' ', '_')
        assert response.headers['Content-Disposition'] == f'attachment; filename={device}_analysis_report.pdf'
        assert get_file_type_from_binary(response.data)['mime'] == 'application/pdf'
