import io
import tarfile

import pytest

from test.common_helper import create_test_firmware


@pytest.fixture(autouse=True)
def _autouse_intercom_backend_binding(intercom_backend_binding):
    pass


class TestAcceptanceDownloadFile:
    def _show_analysis_page(self, test_client, fw):
        rv = test_client.get(f'/analysis/{fw.uid}')
        assert fw.uid.encode() in rv.data
        assert b'test_router' in rv.data
        assert b'Router' in rv.data
        assert b'test_vendor' in rv.data

    def _start_binary_download(self, test_client, uid, contents):
        rv = test_client.get(f'/download/{uid}')
        assert contents in rv.data, 'firmware download unsuccessful'
        assert 'attachment; filename=test.zip' in rv.headers['Content-Disposition']

    def _start_tar_download(self, test_client, uid, contents):
        rv = test_client.get(f'/tar-download/{uid}')
        assert contents not in rv.data, 'tar download yielded original file instead of tar archive'
        with tarfile.open(fileobj=io.BytesIO(rv.data)) as tar_file:
            file_names = ', '.join(tar_file.getnames())
        assert 'testfile1' in file_names, 'test files could not be found in tar download'

    def test_firmware_download(self, backend_db, file_service, test_client):
        test_fw = create_test_firmware()
        contents = test_fw.file_path.read_bytes()
        test_fw.processed_analysis.pop('dummy')
        backend_db.add_object(test_fw)
        file_service.store_file(contents, uid=test_fw.uid)

        self._show_analysis_page(test_client, test_fw)
        self._start_binary_download(test_client, test_fw.uid, contents)
        self._start_tar_download(test_client, test_fw.uid, contents)
