from typing import List

from sqlalchemy import select
from sqlalchemy.orm import Session

from objects.file import FileObject
from objects.firmware import Firmware
from storage_postgresql.db_interface_common import DbInterfaceError, ReadWriteDbInterface
from storage_postgresql.entry_conversion import (
    create_analysis_entries, create_file_object_entry, create_firmware_entry, get_analysis_without_meta
)
from storage_postgresql.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry


class BackendDbInterface(ReadWriteDbInterface):

    # ===== Create / INSERT =====

    def add_object(self, fw_object: FileObject):
        if self.exists(fw_object.uid):
            self.update_object(fw_object)
        else:
            self.insert_object(fw_object)

    def insert_object(self, fw_object: FileObject):
        if isinstance(fw_object, Firmware):
            self.insert_firmware(fw_object)
        else:
            self.insert_file_object(fw_object)
        # ToDo?? self.release_unpacking_lock(fo_fw.uid)

    def insert_file_object(self, file_object: FileObject):
        with self.get_read_write_session() as session:
            fo_entry = create_file_object_entry(file_object)
            self._update_parents(file_object.parent_firmware_uids, file_object.parents, fo_entry, session)
            analyses = create_analysis_entries(file_object, fo_entry)
            session.add_all([fo_entry, *analyses])

    @staticmethod
    def _update_parents(root_fw_uids: List[str], parent_uids: List[str], fo_entry: FileObjectEntry, session: Session):
        for uid in root_fw_uids:
            root_fw = session.get(FileObjectEntry, uid)
            if root_fw not in fo_entry.root_firmware:
                fo_entry.root_firmware.append(root_fw)
        for uid in parent_uids:
            parent = session.get(FileObjectEntry, uid)
            if parent not in fo_entry.parent_files:
                fo_entry.parent_files.append(parent)

    def insert_firmware(self, firmware: Firmware):
        with self.get_read_write_session() as session:
            fo_entry = create_file_object_entry(firmware)
            # fo_entry.root_firmware.append(fo_entry)  # ToDo FixMe??? Should root_fo ref itself?
            # references in fo_entry (e.g. analysis or included files) are populated automatically
            firmware_entry = create_firmware_entry(firmware, fo_entry)
            analyses = create_analysis_entries(firmware, fo_entry)
            session.add_all([fo_entry, firmware_entry, *analyses])

    def add_analysis(self, uid: str, plugin: str, analysis_dict: dict):
        # ToDo: update analysis scheduler for changed signature
        if self.analysis_exists(uid, plugin):
            self.update_analysis(uid, plugin, analysis_dict)
        else:
            self.insert_analysis(uid, plugin, analysis_dict)

    def analysis_exists(self, uid: str, plugin: str) -> bool:
        with self.get_read_only_session() as session:
            query = select(AnalysisEntry).filter_by(uid=uid, plugin=plugin)
            # ToDo: rewrite with session.execute
            return session.query(query.exists()).scalar()

    def insert_analysis(self, uid: str, plugin: str, analysis_dict: dict):
        with self.get_read_write_session() as session:
            fo_backref = session.get(FileObjectEntry, uid)
            if fo_backref is None:
                raise DbInterfaceError('Could not find file object for analysis update')
            analysis = AnalysisEntry(
                uid=uid,
                plugin=plugin,
                plugin_version=analysis_dict['plugin_version'],
                analysis_date=analysis_dict['analysis_date'],
                summary=analysis_dict.get('summary'),
                tags=analysis_dict.get('tags'),
                result=get_analysis_without_meta(analysis_dict),
                file_object=fo_backref,
            )
            session.add(analysis)

    # ===== Update / UPDATE =====

    def update_object(self, fw_object: FileObject):
        if isinstance(fw_object, Firmware):
            self.update_firmware(fw_object)
        self.update_file_object(fw_object)

    def update_firmware(self, firmware: Firmware):
        with self.get_read_write_session() as session:
            entry: FirmwareEntry = session.get(FirmwareEntry, firmware.uid)
            entry.release_date = firmware.release_date
            entry.version = firmware.version
            entry.vendor = firmware.vendor
            entry.device_name = firmware.device_name
            entry.device_class = firmware.device_class
            entry.device_part = firmware.part
            entry.firmware_tags = firmware.tags

    def update_file_object(self, file_object: FileObject):
        with self.get_read_write_session() as session:
            entry: FileObjectEntry = session.get(FileObjectEntry, file_object.uid)
            entry.file_name = file_object.file_name
            entry.depth = file_object.depth
            entry.size = file_object.size
            entry.comments = file_object.comments
            entry.virtual_file_paths = file_object.virtual_file_path
            entry.is_firmware = isinstance(file_object, Firmware)

    def update_analysis(self, uid: str, plugin: str, analysis_data: dict):
        with self.get_read_write_session() as session:
            entry = session.get(AnalysisEntry, (uid, plugin))
            entry.plugin_version = analysis_data['plugin_version']
            entry.analysis_date = analysis_data['analysis_date']
            entry.summary = analysis_data.get('summary')
            entry.tags = analysis_data.get('tags')
            entry.result = get_analysis_without_meta(analysis_data)

    def update_file_object_parents(self, file_uid: str, root_uid: str, parent_uid):
        with self.get_read_write_session() as session:
            fo_entry = session.get(FileObjectEntry, file_uid)
            self._update_parents([root_uid], [parent_uid], fo_entry, session)
