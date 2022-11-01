from pathlib import Path
from tempfile import TemporaryDirectory


class MockFSOrganizer:
    def __init__(self, *_, **__):
        self._data_folder = TemporaryDirectory()

    def store_file(self, file_object):
        Path(self._data_folder.name, file_object.uid).write_bytes(file_object.binary)

    def delete_file(self, uid):
        file_path = Path(self._data_folder.name, uid)
        if file_path.is_file():
            file_path.unlink()

    def generate_path(self, uid):
        return str(Path(self._data_folder.name, uid))

    def __del__(self):
        self._data_folder.cleanup()


class MockDbInterface:
    def __init__(self, *_, **__):
        self._objects = {}

    def add_object(self, fo_fw):
        self._objects[fo_fw.uid] = fo_fw

    def get_analysis(self, *_):
        pass

    def get_specific_fields_of_db_entry(self, uid, field_dict):
        pass


# TODO Is this used? Where should this be patched??
def initialize_config(tmp_dir):
    config = None
    # Database
    config.set('data-storage', 'main-database', 'tmp_integration_tests')
    config.set('data-storage', 'intercom-database-prefix', 'tmp_integration_tests')
    config.set('data-storage', 'statistic-database', 'tmp_integration_tests')
    config.set('data-storage', 'view-storage', 'tmp_view_storage')

    # Analysis
    config.add_section('ip_and_uri_finder')
    config.set('ip_and_uri_finder', 'signature_directory', 'analysis/signatures/ip_and_uri_finder/')
    config.set('default-plugins', 'plugins', 'file_hashes')

    # Unpacker
    config.set('unpack', 'threads', '1')
    config.set('expert-settings', 'unpack-throttle-limit', '20')

    # Compare
    config.set('expert-settings', 'ssdeep-ignore', '80')
    config.set('expert-settings', 'block-delay', '1')
    config.set('expert-settings', 'throw-exceptions', 'true')

    return config
