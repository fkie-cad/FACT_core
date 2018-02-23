from test.common_helper import create_test_firmware
from test.acceptance.base import TestAcceptanceBase
from storage.db_interface_backend import BackEndDbInterface


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
