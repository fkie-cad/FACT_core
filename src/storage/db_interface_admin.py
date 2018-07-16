import logging

from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_common import MongoInterfaceCommon


class AdminDbInterface(MongoInterfaceCommon):

    READ_ONLY = False

    def __init__(self, config=None):
        super().__init__(config=config)
        self.intercom = InterComFrontEndBinding(config=config)

    def shutdown(self):
        self.intercom.shutdown()
        super().shutdown()

    def remove_object_field(self, uid, field):
        current_db = self.firmwares if self.is_firmware(uid) else self.file_objects
        current_db.find_one_and_update(
            {'_id': uid},
            {'$unset': {field: ''}}
        )

    def remove_from_object_array(self, uid, field, value):
        current_db = self.firmwares if self.is_firmware(uid) else self.file_objects
        current_db.find_one_and_update(
            {'_id': uid},
            {'$pull': {field: value}}
        )

    def delete_firmware(self, uid, delete_root_file=True):
        removed_fp, deleted = 0, 1
        fw = self.firmwares.find_one(uid)
        if fw:
            for included_file_uid in fw['files_included']:
                child_removed_fp, child_deleted = self._remove_virtual_path_entries(uid, included_file_uid)
                removed_fp += child_removed_fp
                deleted += child_deleted
            if delete_root_file:
                self.intercom.delete_file(fw)
            self._delete_swapped_analysis_entries(fw)
            self.firmwares.delete_one({'_id': uid})
        else:
            logging.error('Firmware not found in Database: {}'.format(uid))
        return removed_fp, deleted

    def _delete_swapped_analysis_entries(self, fo_entry):
        for key in fo_entry['processed_analysis']:
            try:
                if fo_entry['processed_analysis'][key]['file_system_flag']:
                    for analysis_key in fo_entry['processed_analysis'][key].keys():
                        if analysis_key != 'file_system_flag' and isinstance(fo_entry['processed_analysis'][key][analysis_key], str):
                            sanitize_id = fo_entry['processed_analysis'][key][analysis_key]
                            entry = self.sanitize_fs.find_one({'filename': sanitize_id})
                            self.sanitize_fs.delete(entry._id)
            except KeyError:
                logging.warning('key error while deleting analysis for {}:{}'.format(fo_entry['_id'], key))

    def _remove_virtual_path_entries(self, root_uid, fo_uid):
        '''
        Recursively checks if the provided root uid is the only entry in the virtual path of the file object specified \
        by fo uid. If this is the case, the file object is deleted from the database. Otherwise, only the entry from \
        the virtual path is removed.
        :param root_uid: the uid of the root firmware
        :param fo_uid: he uid of the current file object
        :return: tuple with numbers of recursively removed virtual file path entries and deleted files
        '''
        removed_fp, deleted = 0, 0
        fo = self.file_objects.find_one(fo_uid)
        if fo is not None:
            for child_uid in fo['files_included']:
                child_removed_fp, child_deleted = self._remove_virtual_path_entries(root_uid, child_uid)
                removed_fp += child_removed_fp
                deleted += child_deleted
            if any([root != root_uid for root in fo['virtual_file_path'].keys()]):
                # there are more roots in the virtual path, meaning this file is included in other firmwares
                self.remove_object_field(fo_uid, 'virtual_file_path.{}'.format(root_uid))
                if 'parent_firmware_uids' in fo:
                    self.remove_from_object_array(fo_uid, 'parent_firmware_uids', root_uid)
                removed_fp += 1
            else:
                self._delete_swapped_analysis_entries(fo)
                self._delete_file_object(fo)
                deleted += 1
        return removed_fp, deleted

    def _delete_file_object(self, fo_entry):
        self.intercom.delete_file(fo_entry)
        self.file_objects.delete_one({'_id': fo_entry['_id']})
