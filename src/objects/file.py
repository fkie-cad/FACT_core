import logging
from pathlib import Path
from typing import Optional

from common_helper_files import get_binary_from_file

from helperFunctions.dataConversion import get_value_of_first_key, make_bytes, make_unicode_string
from helperFunctions.hash import get_sha256
from helperFunctions.uid import create_uid
from helperFunctions.virtual_file_path import get_base_of_virtual_path, get_top_of_virtual_path


class FileObject:  # pylint: disable=too-many-instance-attributes
    '''
    This is the base file objects. All files in FACT should be implemented as this object type.

    :param binary: (Optional) The file in binary representation. Either this or file_path has to be present.
    :param file_name: (Optional) The file's name.
    :param file_path: (Optional) The file's path. Either this or binary has to be present.
    :param scheduled_analysis: (Optional) A list of analysis plugins that should be run on this file.
    '''
    def __init__(
            self,
            binary: bytes = None,
            file_name: str = None,
            file_path: str = None,
            scheduled_analysis: list = None
    ):
        self._uid = None

        #: The set of files included in this file. This is usually true for archives.
        #: Only lists the next layer, not recursively included files on lower extraction layers.
        self.files_included: set = set()

        #: The list of all recusively included files in this file.
        #: That means files are included that are themselves included in files contained in this file, and so on.
        #: This value is not set by default as it's expensive to aggregate and takes up a lot of memory.
        self.list_of_all_included_files: Optional[list, None] = None

        self.parents = []
        self.root_uid = None
        self.depth = 0
        self.processed_analysis = {}
        self.scheduled_analysis = scheduled_analysis
        self.comments = []
        self.parent_firmware_uids = set()
        self.temporary_data = {}
        self.analysis_tags = {}
        self.analysis_exception = None
        if binary is not None:
            self.set_binary(binary)
        else:
            self.binary = None
            self.sha256 = None
            self.size = None
        self.file_name = make_unicode_string(file_name) if file_name is not None else file_name
        self.set_file_path(file_path)
        self.virtual_file_path = {}

    def set_binary(self, binary):
        self.binary = make_bytes(binary)
        self.sha256 = get_sha256(self.binary)
        self.size = len(self.binary)
        self._uid = create_uid(binary)

    def set_file_path(self, file_path):
        if file_path is not None:
            if self.binary is None:
                self.create_from_file(file_path)
            if self.file_name is None:
                self.file_name = make_unicode_string(Path(file_path).name)
        self.file_path = file_path

    def get_uid(self):
        logging.warning('Deprecation warning: "get_uid()" was replaced by "uid" and will be removed in a future update')
        return self.uid

    @property
    def uid(self):
        if self._uid is None and self.binary is not None:
            self._uid = create_uid(self.binary)
        return self._uid

    @uid.setter
    def uid(self, new_uid):
        if self._uid is not None:
            logging.warning('uid overwrite: Uid might not be related to binary data anymore: {} -> {}'.format(self._uid, new_uid))
        self._uid = new_uid

    def get_hid(self, root_uid=None):
        '''
        return a human readable identifier
        '''
        if root_uid is None:
            root_uid = self.get_root_uid()
        virtual_path = self.get_virtual_paths_for_one_uid(root_uid=root_uid)[0]
        return get_top_of_virtual_path(virtual_path)

    def create_from_file(self, file_path):
        self.set_binary(get_binary_from_file(file_path))
        self.set_file_path(file_path)

    def add_included_file(self, file_object):
        file_object.parents.append(self.uid)
        file_object.root_uid = self.root_uid
        file_object.add_virtual_file_path_if_none_exists(self.get_virtual_paths_for_one_uid(root_uid=self.root_uid), self.uid)
        file_object.depth = self.depth + 1
        file_object.scheduled_analysis = self.scheduled_analysis
        self.files_included.add(file_object.uid)

    def add_virtual_file_path_if_none_exists(self, parent_paths, parent_uid):
        if self.root_uid not in self.virtual_file_path.keys():
            self.virtual_file_path[self.root_uid] = []
            for item in parent_paths:
                base_path = get_base_of_virtual_path(item)
                if base_path:
                    base_path += "|"
                self.virtual_file_path[self.root_uid].append("{}{}|{}".format(base_path, parent_uid, self.file_path))

    def get_virtual_paths_for_one_uid(self, root_uid=None):
        '''
        returns the virtual path of root_uid if argument set
        if not: returns virtual path of self.root_uid if set
        else: return virtual_paths of first key
        '''
        try:
            file_paths = self.get_virtual_file_paths()
            req_root_uid = root_uid or self.root_uid
            if req_root_uid is None:
                return get_value_of_first_key(file_paths)
            return file_paths[req_root_uid]
        except (AttributeError, IndexError, KeyError, TypeError):
            logging.error('Error on virtual file path retrieval. This should be fixed')
            return ["insufficient information: firmware analysis not complete"]

    def get_virtual_file_paths(self):
        if self.virtual_file_path:
            return self.virtual_file_path
        return {self.uid: [str(self.uid)]}

    def get_root_uid(self):
        if self.root_uid is not None:
            return self.root_uid
        return list(self.get_virtual_file_paths().keys())[0]

    def __str__(self):
        return "UID: {}\n Processed analysis: {}\n Files included: {}".format(self.uid, list(self.processed_analysis.keys()), self.files_included)

    def __repr__(self):
        return self.__str__()
