from __future__ import annotations

import logging

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

    def delete_firmware(self, uid: str):
        with self.get_read_write_session() as session:
            fw = session.get(FileObjectEntry, uid)  # type: FileObjectEntry | None
            if not fw or not fw.is_firmware:
                logging.error(f'Trying to remove FW with UID {uid} but it could not be found in the DB.')
                return
        self.delete_object(uid)

    def delete_comparison(self, comparison_id: str):
        try:
            with self.get_read_write_session() as session:
                session.delete(session.get(ComparisonEntry, comparison_id))
            logging.debug(f'Old comparison deleted: {comparison_id}')
        except Exception as exception:
            logging.warning(f'Could not delete comparison {comparison_id}: {exception}', exc_info=True)
