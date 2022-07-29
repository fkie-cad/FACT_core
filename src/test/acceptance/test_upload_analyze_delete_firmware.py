# pylint: disable=no-self-use
import time
from pathlib import Path

import pytest

from helperFunctions.database import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from storage.fsorganizer import FSOrganizer
from test.common_helper import upload_test_firmware


@pytest.mark.usefixtures('backend_services')
class TestAcceptanceAnalyzeFirmware:

    def _upload_firmware_get(self, test_client, configparser_cfg):
        rv = test_client.get('/upload')
        assert b'<h3 class="mb-3">Upload Firmware</h3>' in rv.data, 'upload page not displayed correctly'

        with ConnectTo(InterComFrontEndBinding, configparser_cfg) as connection:
            plugins = connection.get_available_analysis_plugins()

        mandatory_plugins = [p for p in plugins if plugins[p][1]]
        default_plugins = [p for p in plugins if p != 'unpacker' and plugins[p][2]['default']]
        optional_plugins = [p for p in plugins if not (plugins[p][1] or plugins[p][2])]
        for mandatory_plugin in mandatory_plugins:
            assert f'id="{mandatory_plugin}"'.encode() not in rv.data, f'mandatory plugin {mandatory_plugin} found erroneously'
        for default_plugin in default_plugins:
            assert f'value="{default_plugin}" checked'.encode() in rv.data, f'default plugin {default_plugin} erroneously unchecked or not found'
        for optional_plugin in optional_plugins:
            assert f'value="{optional_plugin}" unchecked'.encode() in rv.data, f'optional plugin {optional_plugin} erroneously checked or not found'

    def _show_analysis_page(self, test_client, test_fw_a, configparser_cfg):
        db = FrontEndDbInterface(configparser_cfg)
        assert db.exists(test_fw_a.uid), 'Error: Test firmware not found in DB!'
        rv = test_client.get(f'/analysis/{test_fw_a.uid}')
        assert test_fw_a.uid.encode() in rv.data
        assert test_fw_a.name.encode() in rv.data
        assert b'test_class' in rv.data
        assert b'test_vendor' in rv.data
        assert b'test_part' in rv.data
        assert b'unknown' in rv.data
        assert test_fw_a.file_name.encode() in rv.data, 'file name not found'
        assert b'Admin</button>' in rv.data, 'admin options not shown with disabled auth'

    def _check_ajax_file_tree_routes(self, test_client, test_fw_a):
        rv = test_client.get(f'/ajax_tree/{test_fw_a.uid}/{test_fw_a.uid}')
        assert b'"children":' in rv.data
        rv = test_client.get(f'/ajax_root/{test_fw_a.uid}/{test_fw_a.uid}')
        assert b'"children":' in rv.data

    def _check_ajax_on_demand_binary_load(self, test_client):
        rv = test_client.get('/ajax_get_binary/text_plain/d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62')
        assert b'test file' in rv.data

    def _show_analysis_details_file_type(self, test_client, test_fw_a):
        rv = test_client.get(f'/analysis/{test_fw_a.uid}/file_type')
        assert b'application/zip' in rv.data
        assert b'Zip archive data' in rv.data
        assert b'<pre><code>' not in rv.data, 'generic template used instead of specific template -> sync view error!'

    def _show_home_page(self, test_client, test_fw_a):
        rv = test_client.get('/')
        assert test_fw_a.uid.encode() in rv.data, 'test firmware not found under recent analysis on home page'

    def _re_do_analysis_get(self, test_client, test_fw_a):
        rv = test_client.get(f'/admin/re-do_analysis/{test_fw_a.uid}')
        assert b'<input type="hidden" name="file_name" id="file_name" value="' + test_fw_a.file_name.encode() + b'">' in rv.data, 'file name not set in re-do page'

    def _delete_firmware(self, test_client, test_fw_a, configparser_cfg):
        fs_backend = FSOrganizer(config=configparser_cfg)
        local_firmware_path = Path(fs_backend.generate_path_from_uid(test_fw_a.uid))
        assert local_firmware_path.exists(), 'file not found before delete'
        rv = test_client.get(f'/admin/delete/{test_fw_a.uid}')
        assert b'Deleted 4 file(s) from database' in rv.data, 'deletion success page not shown'
        rv = test_client.get(f'/analysis/{test_fw_a.uid}')
        assert b'File not found in database' in rv.data, 'file is still available after delete'
        time.sleep(3)
        assert not local_firmware_path.exists(), 'file not deleted'

    def test_run_from_upload_via_show_analysis_to_delete(self, test_client, analysis_finished_event, test_fw_a, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        self._upload_firmware_get(test_client, configparser_cfg)
        upload_test_firmware(test_client, test_fw_a)
        analysis_finished_event.wait(timeout=15)
        self._show_analysis_page(test_client, test_fw_a, configparser_cfg)
        self._show_analysis_details_file_type(test_client, test_fw_a)
        self._check_ajax_file_tree_routes(test_client, test_fw_a)
        self._check_ajax_on_demand_binary_load(test_client)
        self._show_home_page(test_client, test_fw_a)
        self._re_do_analysis_get(test_client, test_fw_a)
        self._delete_firmware(test_client, test_fw_a, configparser_cfg)
