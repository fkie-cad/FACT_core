from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from helperFunctions.virtual_file_path import update_virtual_file_path
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_base import DbInterfaceError, DbSerializationError, ReadWriteDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.entry_conversion import (
    create_analysis_entries,
    create_file_object_entry,
    create_firmware_entry,
    get_analysis_without_meta,
)
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry, VirtualFilePath


class BackendDbInterface(DbInterfaceCommon, ReadWriteDbInterface):

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

    def insert_file_object(self, file_object: FileObject):
        with self.get_read_write_session() as session:
            fo_entry = create_file_object_entry(file_object)
            self._update_parents(file_object.parent_firmware_uids, file_object.parents, fo_entry, session)
            analyses = create_analysis_entries(file_object, fo_entry)
            session.add_all([fo_entry, *analyses])

    def _update_parents(
        self, root_fw_uids: list[str], parent_uids: list[str], fo_entry: FileObjectEntry, session: Session
    ):
        self._update_entries(session, fo_entry.root_firmware, root_fw_uids, 'root')
        self._update_entries(session, fo_entry.parent_files, parent_uids, 'parent')

    @staticmethod
    def _update_entries(session: Session, db_column, uid_list: list[str], label: str):
        entry_list = [session.get(FileObjectEntry, uid) for uid in uid_list]
        if entry_list and not any(entry_list):  # => all None
            raise DbInterfaceError(f'Trying to add object but no {label} object was found in DB: {uid_list}')
        for fo_entry in entry_list:
            if fo_entry is None:
                logging.warning(f'Trying to add object but {label} object was not found in DB: {fo_entry}')
            elif fo_entry and fo_entry not in db_column:
                db_column.append(fo_entry)

    def insert_firmware(self, firmware: Firmware):
        with self.get_read_write_session() as session:
            fo_entry = create_file_object_entry(firmware)
            # references in fo_entry (e.g. analysis or included files) are populated automatically
            firmware_entry = create_firmware_entry(firmware, fo_entry)
            analyses = create_analysis_entries(firmware, fo_entry)
            session.add_all([fo_entry, firmware_entry, *analyses])

    def add_analysis(self, uid: str, plugin: str, analysis_dict: dict):
        try:
            if self.analysis_exists(uid, plugin):
                self.update_analysis(uid, plugin, analysis_dict)
            else:
                self.insert_analysis(uid, plugin, analysis_dict)
        except DbSerializationError:
            logging.exception(
                f'Could not store analysis of plugin result {plugin} in the DB because'
                f' it is not JSON-serializable: {uid}\n{analysis_dict}'
            )
        except DbInterfaceError as error:
            logging.error(f'Could not store analysis result of {plugin} on {uid}: {str(error)}')
        except ValueError as error:
            logging.error(f'Bad value in analysis result of {plugin} on {uid}: {str(error)}\n{analysis_dict}')
            raise

    def analysis_exists(self, uid: str, plugin: str) -> bool:
        with self.get_read_only_session() as session:
            query = select(AnalysisEntry.uid).filter_by(uid=uid, plugin=plugin)
            return bool(session.execute(query).scalar())

    def insert_analysis(self, uid: str, plugin: str, analysis_dict: dict):
        with self.get_read_write_session() as session:
            fo_backref = session.get(FileObjectEntry, uid)
            if fo_backref is None:
                raise DbInterfaceError(f'Could not find file object for analysis update: {uid}')
            if any(item not in analysis_dict for item in ['plugin_version', 'analysis_date']):
                raise DbInterfaceError(f'Analysis data of {plugin} is incomplete: {analysis_dict}')
            analysis = AnalysisEntry(
                uid=uid,
                plugin=plugin,
                plugin_version=analysis_dict['plugin_version'],
                system_version=analysis_dict.get('system_version'),
                analysis_date=analysis_dict['analysis_date'],
                summary=analysis_dict.get('summary'),
                tags=analysis_dict.get('tags'),
                result=get_analysis_without_meta(analysis_dict),
                file_object=fo_backref,
            )
            session.add(analysis)

    def add_vfp(self, parent_uid: str, child_uid: str, path: str):
        """Adds a new "virtual file path" for file `child_uid` with path `path` in `parent_uid`"""
        with self.get_read_write_session() as session:
            child_fo = session.get(FileObjectEntry, child_uid)
            parent_fo = session.get(FileObjectEntry, parent_uid)
            if child_fo is None or parent_fo is None:
                logging.error(
                    f'Could not store VFP because either parent "{parent_uid}" or child "{child_uid}" was not found'
                )
                return
            vfp = VirtualFilePath(
                parent_uid=parent_uid,
                file_uid=child_uid,
                file_path=path,
                _file_object=child_fo,
                _parent_object=parent_fo,
            )
            session.add(vfp)

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
            entry.virtual_file_paths = update_virtual_file_path(file_object.virtual_file_path, entry.virtual_file_paths)
            entry.is_firmware = isinstance(file_object, Firmware)
            self._update_parents(file_object.parent_firmware_uids, file_object.parents, entry, session)

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
