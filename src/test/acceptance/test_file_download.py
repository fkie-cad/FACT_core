# pylint: disable=no-self-use
import io
import tarfile

from test.common_helper import create_test_firmware  # pylint: disable=wrong-import-order


class TestAcceptanceDownloadFile:

    def _show_analysis_page(self, test_client, fw):
        rv = test_client.get(f'/analysis/{fw.uid}')
        assert fw.uid.encode() in rv.data
        assert b'test_router' in rv.data
        assert b'Router' in rv.data
        assert b'test_vendor' in rv.data

    def _start_binary_download(self, test_client, fw):
        rv = test_client.get(f'/download/{fw.uid}')
        assert fw.binary in rv.data, 'firmware download unsuccessful'
        assert 'attachment; filename=test.zip' in rv.headers['Content-Disposition']

    def _start_tar_download(self, test_client, fw):
        rv = test_client.get(f'/tar-download/{fw.uid}')
        assert fw.binary not in rv.data, 'tar download yielded original file instead of tar archive'
        with tarfile.open(fileobj=io.BytesIO(rv.data)) as tar_file:
            contents = ', '.join(tar_file.getnames())
        assert 'testfile1' in contents, 'test files could not be found in tar download'

    def test_firmware_download(self, backend_services, test_client):
        test_fw = create_test_firmware()
        test_fw.processed_analysis.pop('dummy')
        test_fw.uid = test_fw.uid
        backend_services.db_backend_interface.add_object(test_fw)
        backend_services.fs_organizer.store_file(test_fw)

        self._show_analysis_page(test_client, test_fw)
        self._start_binary_download(test_client, test_fw)
        self._start_tar_download(test_client, test_fw)
