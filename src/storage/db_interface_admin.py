from __future__ import annotations

import logging

from sqlalchemy import select

from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_connection import DbConnection, ReadWriteDeleteConnection
from storage.db_interface_base import ReadWriteDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.schema import ComparisonEntry, FileObjectEntry


class AdminDbInterface(DbInterfaceCommon, ReadWriteDbInterface):
    def __init__(self, connection: DbConnection | None = None, intercom=None):
        self.intercom = InterComFrontEndBinding() if intercom is None else intercom
        super().__init__(connection=connection or ReadWriteDeleteConnection())

    # ===== Delete / DELETE =====

    def delete_object(self, uid: str):
        with self.get_read_write_session() as session:
            fo_entry = session.get(FileObjectEntry, uid)
            if fo_entry is not None:
                session.delete(fo_entry)

    def delete_firmware(self, uid: str, delete_root_file: bool = True) -> tuple[int, int]:
        with self.get_read_write_session() as session:
            fw: FileObjectEntry = session.get(FileObjectEntry, uid)
            if not fw or not fw.is_firmware:
                logging.error(f'Trying to remove FW with UID {uid} but it could not be found in the DB.')
                return 0, 0
            included_uids = self.get_all_files_in_fw(fw.uid)
            self.delete_object(uid)
            # DB entries of files that only belonged to this FW are deleted by event listener `delete_file_orphans()`
            # DB entries of files that also belong to other FW should still be there but the VFP needs to be updated
            still_in_db = self._update_vfp_entries(uid, included_uids, session)
        # if we subtract the updated files from all files that belonged to the FW we get the files that need to be
        # deleted from the file system (through the "intercom")
        uids_to_delete = included_uids - still_in_db
        if delete_root_file:
            uids_to_delete.add(uid)
        self.intercom.delete_file(list(uids_to_delete))
        return len(still_in_db), len(uids_to_delete)

    def delete_comparison(self, comparison_id: str):
        try:
            with self.get_read_write_session() as session:
                session.delete(session.get(ComparisonEntry, comparison_id))
            logging.debug(f'Old comparison deleted: {comparison_id}')
        except Exception as exception:
            logging.warning(f'Could not delete comparison {comparison_id}: {exception}', exc_info=True)

    @staticmethod
    def _update_vfp_entries(root_uid: str, included_files: set[str], session) -> set[str]:
        """
        :param root_uid: The UID of the deleted FW
        :param included_files: A set of UIDs of all files included in the FW
        :param session: The current DB session
        :return: A set of UIDs from files included in the deleted FW that are still in the DB (because they are also
            included in another FW) and whose virtual file paths were updated (i.e. entries of FW were removed)
        """
        files_still_in_db = set()
        query = select(FileObjectEntry).filter(FileObjectEntry.uid.in_(included_files))
        for fo_entry in session.execute(query).scalars():  # type: FileObjectEntry
            files_still_in_db.add(fo_entry.uid)
            fo_entry.virtual_file_paths = {
                uid: path_list
                for uid, path_list in fo_entry.virtual_file_paths.items()
                if uid != root_uid  # remove the VFP entries of the deleted FW
            }
        return files_still_in_db
