import os
import time

from helperFunctions.fileSystem import get_test_data_dir
from helperFunctions.web_interface import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from test.acceptance.base import TestAcceptanceBase


class TestAcceptanceAnalyzeFirmware(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        time.sleep(10)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def _upload_firmware_get(self):
        print('- upload firmware -> get ...')
        rv = self.test_client.get('/upload')
        self.assertIn(b'<h2>Upload Firmware</h2>', rv.data, 'upload page not displayed correctly')

        with ConnectTo(InterComFrontEndBinding, self.config) as connection:
            plugins = connection.get_available_analysis_plugins()

        mandatory_plugins = [p for p in plugins if plugins[p][1]]
        default_plugins = [p for p in plugins if plugins[p][2]]
        optional_plugins = [p for p in plugins if not (plugins[p][1] or plugins[p][2])]
        for mandatory_plugin in mandatory_plugins:
            self.assertNotIn(mandatory_plugin.encode(), rv.data, 'mandatory plugin {} found erroneously'.format(mandatory_plugin))
        for default_plugin in default_plugins:
            self.assertIn('value="{}" checked'.format(default_plugin).encode(), rv.data,
                          'default plugin {} erroneously unchecked or not found'.format(default_plugin))
        for optional_plugin in optional_plugins:
            self.assertIn('value="{}" unchecked'.format(optional_plugin).encode(), rv.data,
                          'optional plugin {} erroneously checked or not found'.format(optional_plugin))

    def _upload_firmware_post(self):
        print('- upload firmware -> post ...')
        testfile_path = os.path.join(get_test_data_dir(), self.test_fw_a.path)
        with open(testfile_path, 'rb') as fp:
            data = {
                'file': (fp, self.test_fw_a.file_name),
                'device_name': 'test_device',
                'device_class': 'test_class',
                'firmware_version': '1.0',
                'vendor': 'test_vendor',
                'release_date': '1970-01-01',
                'analysis_systems': []
            }
            rv = self.test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)
        self.assertIn(b'Upload Successful', rv.data, 'upload not successful')
        self.assertIn(self.test_fw_a.uid.encode(), rv.data, 'uid not found on upload success page')

    def _show_analysis_page(self):
        print('- show analysis ...')
        with ConnectTo(FrontEndDbInterface, self.config) as connection:
            self.assertIsNotNone(connection.firmwares.find_one({'_id': self.test_fw_a.uid}), 'Error: Test firmware not found in DB!')
        rv = self.test_client.get('/analysis/{}'.format(self.test_fw_a.uid))
        self.assertIn(self.test_fw_a.uid.encode(), rv.data)
        self.assertIn(b'test_device', rv.data)
        self.assertIn(b'test_class', rv.data)
        self.assertIn(b'test_vendor', rv.data)
        self.assertIn(b'unknown', rv.data)
        self.assertIn(self.test_fw_a.file_name.encode(), rv.data, 'file name not found')

    def _check_ajax_file_tree_routes(self):
        print('- check ajax file tree ...')
        rv = self.test_client.get('/ajax_tree/{}/{}'.format(self.test_fw_a.uid, self.test_fw_a.uid))
        self.assertIn(b'"children":', rv.data)
        rv = self.test_client.get('/ajax_root/{}'.format(self.test_fw_a.uid))
        self.assertIn(b'"children":', rv.data)

    def _check_ajax_on_demand_binary_load(self):
        print('- check ajax on demand binary load ...')
        rv = self.test_client.get('/ajax_get_binary/text_plain/d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62')
        self.assertIn(b'test file', rv.data)

    def _show_analysis_details_file_type(self):
        print('- show analysis detail ...')
        rv = self.test_client.get('/analysis/{}/file_type'.format(self.test_fw_a.uid))
        self.assertIn(b'application/zip', rv.data)
        self.assertIn(b'Zip archive data', rv.data)
        self.assertNotIn(b'<pre><code>', rv.data, 'generic template used instead of specific template -> sync view error!')

    def _show_home_page(self):
        print('- check for entry on recent analysis ...')
        rv = self.test_client.get('/')
        self.assertIn(self.test_fw_a.uid.encode(), rv.data, 'test firmware not found under recent analysis on home page')

    def _re_do_analysis_get(self):
        print('- re-do analysis -> get ...')
        rv = self.test_client.get('/admin/re-do_analysis/{}'.format(self.test_fw_a.uid))
        self.assertIn(b'<input type="hidden" name="file_name" id="file_name" value="' + self.test_fw_a.file_name.encode() + b'">', rv.data, 'file name not set in re-do page')

    def test_run_from_upload_to_show_analysis(self):
        self._upload_firmware_get()
        self._upload_firmware_post()
        time.sleep(15)  # wait for analysis to complete
        self._show_analysis_page()
        self._show_analysis_details_file_type()
        self._check_ajax_file_tree_routes()
        self._check_ajax_on_demand_binary_load()
        self._show_home_page()
        self._re_do_analysis_get()
