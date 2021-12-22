import logging
from typing import Tuple

from storage_postgresql.db_interface_base import ReadWriteDbInterface
from storage_postgresql.db_interface_common import DbInterfaceCommon
from storage_postgresql.schema import FileObjectEntry


class AdminDbInterface(DbInterfaceCommon, ReadWriteDbInterface):

    def __init__(self, database='fact_db', config=None, intercom=None):
        super().__init__(database=database)
        if intercom is not None:  # for testing purposes
            self.intercom = intercom
        else:
            from intercom.front_end_binding import InterComFrontEndBinding
            self.intercom = InterComFrontEndBinding(config=config)  # FixMe? still uses MongoDB

    def shutdown(self):
        self.intercom.shutdown()  # FixMe? still uses MongoDB

    # ===== Delete / DELETE =====

    def delete_object(self, uid: str):
        with self.get_read_write_session() as session:
            fo_entry = session.get(FileObjectEntry, uid)
            if fo_entry is not None:
                session.delete(fo_entry)

    def delete_firmware(self, uid, delete_root_file=True):
        removed_fp, deleted = 0, 0
        with self.get_read_write_session() as session:
            fw: FileObjectEntry = session.get(FileObjectEntry, uid)
            if not fw or not fw.is_firmware:
                logging.error(f'Trying to remove FW with UID {uid} but it could not be found in the DB.')
                return 0, 0

            for child_uid in fw.get_included_uids():
                child_removed_fp, child_deleted = self._remove_virtual_path_entries(uid, child_uid, session)
                removed_fp += child_removed_fp
                deleted += child_deleted
            if delete_root_file:
                self.intercom.delete_file(fw)
            self.delete_object(uid)
            deleted += 1
        return removed_fp, deleted

    def _remove_virtual_path_entries(self, root_uid: str, fo_uid: str, session) -> Tuple[int, int]:
        '''
        Recursively checks if the provided root_uid is the only entry in the virtual path of the file object belonging
        to fo_uid. If this is the case, the file object is deleted from the database. Otherwise, only the entry from
        the virtual path is removed.

        :param root_uid: The uid of the root firmware
        :param fo_uid: The uid of the current file object
        :return: tuple with numbers of recursively removed virtual file path entries and deleted files
        '''
        removed_fp, deleted = 0, 0
        fo_entry: FileObjectEntry = session.get(FileObjectEntry, fo_uid)
        if fo_entry is None:
            return 0, 0
        for child_uid in fo_entry.get_included_uids():
            child_removed_fp, child_deleted = self._remove_virtual_path_entries(root_uid, child_uid, session)
            removed_fp += child_removed_fp
            deleted += child_deleted
        if any(root != root_uid for root in fo_entry.virtual_file_paths):
            # file is included in other firmwares -> only remove root_uid from virtual_file_paths
            fo_entry.virtual_file_paths = {
                uid: path_list
                for uid, path_list in fo_entry.virtual_file_paths.items()
                if uid != root_uid
            }
            # fo.parent_files = [f for f in fo.parent_files if f.uid != root_uid]  # TODO?
            removed_fp += 1
        else:  # file is only included in this firmware -> delete file
            fo = self.get_object(fo_uid)
            self.intercom.delete_file(fo)
            deleted += 1  # FO DB entry gets deleted automatically when all parents are deleted by cascade
        return removed_fp, deleted
