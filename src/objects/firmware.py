from objects.file import FileObject
from helperFunctions.hash import get_md5
from contextlib import suppress


class Firmware(FileObject):
    '''
    This objects represents a firmware
    '''

    def __init__(self, binary=None, file_name=None, file_path=None, scheduled_analysis=None):
        super().__init__(binary=binary, file_name=file_name, file_path=file_path, scheduled_analysis=scheduled_analysis)
        self.device_name = None
        self.version = None
        self.device_class = None
        self.vendor = None
        self.release_date = None
        self.tags = set()
        self._update_root_id_and_virtual_path()

    def set_device_name(self, device_name):
        self.device_name = device_name

    def set_firmware_version(self, version):
        self.version = version

    def set_device_class(self, device_class):
        self.device_class = device_class

    def set_binary(self, binary):
        super().set_binary(binary)
        self._update_root_id_and_virtual_path()
        self.md5 = get_md5(binary)

    def set_vendor(self, vendor):
        self.vendor = vendor

    def set_release_date(self, release_date):
        self.release_date = release_date

    def _update_root_id_and_virtual_path(self):
        self.root_uid = self.get_uid()
        self.virtual_file_path = {self.get_uid(): [self.get_uid()]}

    def set_tag(self, tag):
        self.tags.add(tag)

    def remove_tag(self, tag):
        with suppress(KeyError):
            self.tags.remove(tag)

    def get_hid(self, root_uid=None):
        '''
        return a human readable identifier
        '''
        return '{} {} - {}'.format(self.vendor, self.device_name, self.version)

    def __str__(self):
        return 'Device Name: {}\nFW Version: {}\nProcessed Analysis: {}\nScheduled Analysis: {}'.format(self.device_name, self.version, list(self.processed_analysis.keys()), self.scheduled_analysis)

    def __repr__(self):
        return self.__str__()
