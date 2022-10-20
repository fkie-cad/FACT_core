import time
from pathlib import Path

from helperFunctions.database import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from storage.fsorganizer import FSOrganizer
from test.acceptance.base_full_start import TestAcceptanceBaseFullStart  # pylint: disable=wrong-import-order


class TestAcceptanceAnalyzeFirmware(TestAcceptanceBaseFullStart):
    def _upload_firmware_get(self):
        rv = self.test_client.get('/upload')
        self.assertIn(b'<h3 class="mb-3">Upload Firmware</h3>', rv.data, 'upload page not displayed correctly')

        with ConnectTo(InterComFrontEndBinding, self.config) as connection:
            plugins = connection.get_available_analysis_plugins()

        mandatory_plugins = [p for p in plugins if plugins[p][1]]
        default_plugins = [p for p in plugins if p != 'unpacker' and plugins[p][2]['default']]
        optional_plugins = [p for p in plugins if not (plugins[p][1] or plugins[p][2])]
        for mandatory_plugin in mandatory_plugins:
            self.assertNotIn(
                f'id="{mandatory_plugin}"'.encode(), rv.data, f'mandatory plugin {mandatory_plugin} found erroneously'
            )
        for default_plugin in default_plugins:
            self.assertIn(
                f'value="{default_plugin}" checked'.encode(),
                rv.data,
                f'default plugin {default_plugin} erroneously unchecked or not found',
            )
        for optional_plugin in optional_plugins:
            self.assertIn(
                f'value="{optional_plugin}" unchecked'.encode(),
                rv.data,
                f'optional plugin {optional_plugin} erroneously checked or not found',
            )

    def _show_analysis_page(self):
        db = FrontEndDbInterface(self.config)
        assert db.exists(self.test_fw_a.uid), 'Error: Test firmware not found in DB!'
        rv = self.test_client.get(f'/analysis/{self.test_fw_a.uid}')
        self.assertIn(self.test_fw_a.uid.encode(), rv.data)
        self.assertIn(self.test_fw_a.name.encode(), rv.data)
        self.assertIn(b'test_class', rv.data)
        self.assertIn(b'test_vendor', rv.data)
        self.assertIn(b'test_part', rv.data)
        self.assertIn(b'unknown', rv.data)
        self.assertIn(self.test_fw_a.file_name.encode(), rv.data, 'file name not found')
        self.assertIn(b'Admin</button>', rv.data, 'admin options not shown with disabled auth')

    def _check_ajax_file_tree_routes(self):
        rv = self.test_client.get(f'/ajax_tree/{self.test_fw_a.uid}/{self.test_fw_a.uid}')
        self.assertIn(b'"children":', rv.data)
        rv = self.test_client.get(f'/ajax_root/{self.test_fw_a.uid}/{self.test_fw_a.uid}')
        self.assertIn(b'"children":', rv.data)

    def _check_ajax_on_demand_binary_load(self):
        rv = self.test_client.get(
            '/ajax_get_binary/text_plain/d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62'
        )
        self.assertIn(b'test file', rv.data)

    def _show_analysis_details_file_type(self):
        rv = self.test_client.get(f'/analysis/{self.test_fw_a.uid}/file_type')
        self.assertIn(b'application/zip', rv.data)
        self.assertIn(b'Zip archive data', rv.data)
        self.assertNotIn(
            b'<pre><code>', rv.data, 'generic template used instead of specific template -> sync view error!'
        )

    def _show_home_page(self):
        rv = self.test_client.get('/')
        self.assertIn(
            self.test_fw_a.uid.encode(), rv.data, 'test firmware not found under recent analysis on home page'
        )

    def _re_do_analysis_get(self):
        rv = self.test_client.get(f'/admin/re-do_analysis/{self.test_fw_a.uid}')
        self.assertIn(
            b'<input type="hidden" name="file_name" id="file_name" value="' + self.test_fw_a.file_name.encode() + b'">',
            rv.data,
            'file name not set in re-do page',
        )

    def _delete_firmware(self):
        fs_backend = FSOrganizer(config=self.config)
        local_firmware_path = Path(fs_backend.generate_path_from_uid(self.test_fw_a.uid))
        self.assertTrue(local_firmware_path.exists(), 'file not found before delete')
        rv = self.test_client.get(f'/admin/delete/{self.test_fw_a.uid}')
        self.assertIn(b'Deleted 4 file(s) from database', rv.data, 'deletion success page not shown')
        rv = self.test_client.get(f'/analysis/{self.test_fw_a.uid}')
        self.assertIn(b'File not found in database', rv.data, 'file is still available after delete')
        time.sleep(3)
        self.assertFalse(local_firmware_path.exists(), 'file not deleted')

    def test_run_from_upload_via_show_analysis_to_delete(self):
        self._upload_firmware_get()
        self.upload_test_firmware(self.test_fw_a)
        self.analysis_finished_event.wait(timeout=15)
        self._show_analysis_page()
        self._show_analysis_details_file_type()
        self._check_ajax_file_tree_routes()
        self._check_ajax_on_demand_binary_load()
        self._show_home_page()
        self._re_do_analysis_get()
        self._delete_firmware()
