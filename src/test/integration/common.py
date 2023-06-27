from pathlib import Path
from tempfile import TemporaryDirectory


class MockFSOrganizer:
    def __init__(self, *_, **__):
        self._data_folder = TemporaryDirectory()

    def store_file(self, file_object):
        destination_path = Path(self.generate_path_from_uid(file_object.uid))
        destination_path.write_bytes(file_object.binary)
        file_object.file_path = str(destination_path)

    def delete_file(self, uid):
        file_path = Path(self._data_folder.name, uid)
        if file_path.is_file():
            file_path.unlink()

    def generate_path(self, file_object):
        return self.generate_path_from_uid(file_object.uid)

    def generate_path_from_uid(self, uid):
        return str(Path(self._data_folder.name) / uid)

    def shutdown(self):
        self._data_folder.cleanup()

    def __del__(self):
        self.shutdown()


class MockDbInterface:
    def __init__(self, *_, **__):
        self._objects = {}

    def add_object(self, fo_fw):
        self._objects[fo_fw.uid] = fo_fw

    def get_analysis(self, *_):
        pass

    def add_analysis(self, *_):
        pass

    def get_specific_fields_of_db_entry(self, uid, field_dict):
        pass
