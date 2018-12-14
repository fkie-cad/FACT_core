import logging
import os

from common_helper_files import get_binary_from_file

from helperFunctions.dataConversion import make_bytes, make_unicode_string, get_value_of_first_key
from helperFunctions.hash import get_sha256
from helperFunctions.uid import create_uid


class FileObject(object):
    '''
    This is the base file objects. All files in FAF should be implemented as this object type.
    '''

    def __init__(self, binary=None, file_name=None, file_path=None, scheduled_analysis=None):
        self.uid = None
        self.files_included = set()
        self.list_of_all_included_files = None
        self.parents = []
        self.root_uid = None
        self.depth = 0
        self.processed_analysis = {}
        self.scheduled_analysis = scheduled_analysis
        self.comments = []
        self.parent_firmware_uids = set()
        self.temporary_data = {}
        self.analysis_tags = {}
        if binary is not None:
            self.set_binary(binary)
        else:
            self.binary = None
            self.sha256 = None
            self.size = None
        if file_name is not None:
            self.set_name(file_name)
        else:
            self.file_name = None
        if file_path is not None:
            self.set_file_path(file_path)
        else:
            self.file_path = None
        self.virtual_file_path = {}

    def set_binary(self, binary):
        self.binary = make_bytes(binary)
        self.sha256 = get_sha256(self.binary)
        self.size = len(self.binary)
        self.uid = create_uid(binary)

    def set_name(self, name):
        self.file_name = make_unicode_string(name)

    def set_file_path(self, file_path):
        self.file_path = file_path
        if self.binary is None:
            self.create_from_file(file_path)
        if self.file_name is None:
            self.set_name(os.path.basename(file_path))

    def get_uid(self):
        if self.uid is None and self.binary is not None:
            self.uid = create_uid(self.binary)
        return self.uid

    def overwrite_uid(self, new_uid):
        if self.uid is not None:
            logging.warning("uid overwrite: Uid might not be related to binary data anymore: {} -> {}".format(self.uid, new_uid))
        self.uid = new_uid

    def get_hid(self, root_uid=None):
        '''
        return a human readable identifier
        '''
        if root_uid is not None:
            self.root_uid = root_uid
        tmp = self.get_virtual_paths_for_one_uid(root_uid=self.get_root_uid())[0]
        return self.get_top_of_virtual_path(tmp)

    def get_included_files_uids(self):
        return self.files_included

    def create_from_file(self, file_path):
        self.set_binary(get_binary_from_file(file_path))
        self.set_file_path(file_path)

    def add_included_file(self, file_object):
        file_object.parents.append(self.get_uid())
        file_object.root_uid = self.root_uid
        file_object.add_virtual_file_path_if_none_exists(self.get_virtual_paths_for_one_uid(root_uid=self.root_uid), self.get_uid())
        file_object.depth = self.depth + 1
        file_object.scheduled_analysis = self.scheduled_analysis
        self.files_included.add(file_object.get_uid())

    def add_virtual_file_path_if_none_exists(self, parent_pathes, parent_uid):
        if self.root_uid not in self.virtual_file_path.keys():
            self.virtual_file_path[self.root_uid] = []
            for item in parent_pathes:
                base_path = self.get_base_of_virtual_path(item)
                if len(base_path) > 0:
                    base_path += "|"
                self.virtual_file_path[self.root_uid].append("{}{}|{}".format(base_path, parent_uid, self.file_path))

    def get_virtual_paths_for_one_uid(self, root_uid=None):
        '''
        returns the virtual path of root_uid if argument set
        if not: returns virtual path of self.root_uid if set
        else: return virtual_pathes of first key
        '''
        try:
            file_paths = self.get_virtual_file_paths()
            if root_uid is not None:
                req_root_uid = root_uid
            else:
                req_root_uid = self.root_uid
            if req_root_uid is None:
                return get_value_of_first_key(file_paths)
            else:
                return file_paths[req_root_uid]
        except Exception:
            logging.error('Error on virtual file path retrieval. This should be fixed')
            return ["insufficient information: firmware analysis not complete"]

    def get_virtual_file_paths(self):
        if len(self.virtual_file_path.keys()) > 0:
            return self.virtual_file_path
        else:
            return {self.get_uid(): ['{}'.format(self.get_uid())]}

    @staticmethod
    def get_root_of_virtual_path(virtual_path):
        return virtual_path.split("|")[0]

    @staticmethod
    def get_base_of_virtual_path(virtual_path):
        return "|".join(virtual_path.split("|")[:-1])

    @staticmethod
    def get_top_of_virtual_path(virtual_path):
        return virtual_path.split("|")[-1]

    def get_root_uid(self):
        if self.root_uid is not None:
            return self.root_uid
        else:
            return list(self.get_virtual_file_paths().keys())[0]

    def __str__(self):
        return "UID: {}\n Processed analysis: {}\n Files included: {}".format(self.get_uid(), list(self.processed_analysis.keys()), self.files_included)

    def __repr__(self):
        return self.__str__()
