from fact_helper_file import get_file_type_from_binary
from storage.db_interface_backend import BackEndDbInterface
from storage.db_interface_compare import CompareDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import create_test_firmware

COMPARE_RESULT = {
    'general': {
        'a': {'id1': '<empty>', 'id2': '<empty>'},
        'b': {'id1': '<empty>', 'id2': '<empty>'}
    },
    'plugins': {
        'Ida_Diff_Highlighting': {
            'idb_binary': b'The IDA database'
        }
    }
}

BASE64_ANALYSIS = {
    'summary': ['Base64 code detected'],
    '1019 - 1882': [
        {
            'size': 636,
            'id': 0,
            'span_in_binary': (1019, 1882),
            'span_in_section': (0, 848, 2),
            'filetype': {
                'mime': 'application/octet-stream',
                'full': 'data'
            },
            'strings': (0, []),
            'entropy': 0.9536076771502972
        },
    ]
}


def throwing_function(binary):
    raise Exception('I take exception to everything')


class TestAcceptanceIoRoutes(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend_interface = BackEndDbInterface(self.config)
        self.test_fw = create_test_firmware(device_name='test_fw')
        self.test_fw.processed_analysis['base64_decoder'] = BASE64_ANALYSIS

    def tearDown(self):
        self.db_backend_interface.shutdown()
        self._stop_backend()
        super().tearDown()

    def test_base64_download_success(self):
        self.test_fw.processed_analysis['base64_decoder']['1019 - 1882'][0]['span_in_section'] = (0, 848, 2)
        self.test_fw.processed_analysis['base64_decoder']['1019 - 1882'][0]['span_in_binary'] = (1019, 1882)
        self.db_backend_interface.add_firmware(self.test_fw)

        response = self.test_client.get('/base64-download/{uid}/{section}/{expression_id}'.format(uid=self.test_fw.uid, section='1019 - 1882', expression_id='0'))
        self.assertIn('200', response.status, 'base64 download failed')

    def test_base64_download_bad_result(self):
        self.test_fw.processed_analysis['base64_decoder']['1019 - 1882'][0]['span_in_binary'] = None
        self.db_backend_interface.add_firmware(self.test_fw)

        response = self.test_client.get('/base64-download/{uid}/{section}/{expression_id}'.format(uid=self.test_fw.uid, section='1019 - 1882', expression_id='0'))
        self.assertIn(b'Undisclosed error in base64 decoding', response.data, 'base64 download should break')

    def test_bad_base64_encoding(self):
        self.test_fw.processed_analysis['base64_decoder']['1019 - 1882'][0]['span_in_section'] = (8, 100, 2)
        self.test_fw.processed_analysis['base64_decoder']['1019 - 1882'][0]['span_in_binary'] = (0, 1000)
        self.db_backend_interface.add_firmware(self.test_fw)

        response = self.test_client.get('/base64-download/{uid}/{section}/{expression_id}'.format(uid=self.test_fw.uid, section='1019 - 1882', expression_id='0'))
        self.assertIn(b'Incorrect padding', response.data, 'base64 did not break')

    def test_hex_dump_button(self):
        response = self.test_client.get('/hex-dump/{uid}'.format(uid=self.test_fw.uid))
        self.assertIn('200', response.status, 'hex dump link failed')
        self.assertIn(b'File not found in database', response.data, 'hex dump should fail on missing uid')

        self.db_backend_interface.add_firmware(self.test_fw)

        response = self.test_client.get('/hex-dump/{uid}'.format(uid=self.test_fw.uid))
        self.assertIn('200', response.status, 'hex dump link failed')
        self.assertIn(b'0x0', response.data, 'no hex dump is shown')

    def test_radare_button(self):
        response = self.test_client.get('/radare-view/{uid}'.format(uid=self.test_fw.uid))
        self.assertIn('200', response.status, 'radare view link failed')
        self.assertIn(b'File not found in database', response.data, 'radare view should fail on missing uid')

        self.db_backend_interface.add_firmware(self.test_fw)

        response = self.test_client.get('/radare-view/{uid}'.format(uid=self.test_fw.uid))
        self.assertIn('200', response.status, 'radare view link failed')
        self.assertIn(b'with url: /v1/retrieve', response.data, 'error coming from wrong request')
        self.assertIn(b'Failed to establish a new connection', response.data, 'connection shall fail')

    def test_hex_dump_bad_uid(self):
        response = self.test_client.get('/hex-dump/{uid}'.format(uid=self.test_fw.uid))
        self.assertIn(b'File not found in database', response.data, 'uid should not exist')

    def test_ida_download(self):
        compare_interface = CompareDbInterface(config=self.config)

        self.db_backend_interface.add_firmware(self.test_fw)

        COMPARE_RESULT['general'] = {'a': {self.test_fw.uid: 'x'}, 'b': {self.test_fw.uid: 'y'}}

        compare_interface.add_compare_result(COMPARE_RESULT)
        cid = compare_interface._calculate_compare_result_id(COMPARE_RESULT)

        response = self.test_client.get('/ida-download/{cid}'.format(cid=cid))
        self.assertIn(b'IDA database', response.data, 'mocked ida database not in result')

    def test_ida_download_bad_uid(self):
        compare_interface = CompareDbInterface(config=self.config)

        compare_interface.add_compare_result(COMPARE_RESULT)
        cid = compare_interface._calculate_compare_result_id(COMPARE_RESULT)

        response = self.test_client.get('/ida-download/{cid}'.format(cid=cid))
        self.assertIn(b'not found in database', response.data, 'endpoint should dismiss result')

    def test_pdf_download(self):
        response = self.test_client.get('/pdf-download/{uid}'.format(uid=self.test_fw.uid))
        assert response.status_code == 200, 'pdf download link failed'
        assert b'File not found in database' in response.data, 'radare view should fail on missing uid'

        self.db_backend_interface.add_firmware(self.test_fw)

        response = self.test_client.get('/pdf-download/{uid}'.format(uid=self.test_fw.uid))

        assert response.status_code == 200, 'pdf download failed'
        assert response.headers['Content-Disposition'] == 'attachment; filename={}_analysis_report.pdf'.format(self.test_fw.device_name.replace(' ', '_'))
        assert get_file_type_from_binary(response.data)['mime'] == 'application/pdf'
