from __future__ import annotations

import logging
from contextlib import suppress
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from objects.firmware import Firmware
from storage.db_interface_base import DbInterfaceError, DbSerializationError, ReadWriteDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.entry_conversion import (
    create_analysis_entries,
    create_file_object_entry,
    create_firmware_entry,
    create_vfp_entries,
    sanitize,
)
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry, VirtualFilePath, included_files_table

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from objects.file import FileObject


class BackendDbInterface(DbInterfaceCommon, ReadWriteDbInterface):
    # ===== Create / INSERT =====

    def add_object(self, fw_object: FileObject):
        if self.exists(fw_object.uid):
            self.update_object(fw_object)
        else:
            self.insert_object(fw_object)

    def insert_multiple_objects(self, *objects: FileObject):
        """Convenience method mostly for tests. Careful: order does matter!"""
        for obj in objects:
            self.insert_object(obj)

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
            vfp_entries = create_vfp_entries(file_object)
            session.add_all([fo_entry, *analyses, *vfp_entries])

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
            logging.error(f'Could not store analysis result of {plugin} on {uid}: {error!s}\n{analysis_dict}')
        except ValueError as error:
            logging.error(f'Bad value in analysis result of {plugin} on {uid}: {error!s}\n{analysis_dict}')
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

            result = analysis_dict.get('result', {})
            if result is not None:
                sanitize(result)

            analysis = AnalysisEntry(
                uid=uid,
                plugin=plugin,
                plugin_version=analysis_dict['plugin_version'],
                system_version=analysis_dict.get('system_version'),
                analysis_date=analysis_dict['analysis_date'],
                summary=analysis_dict.get('summary'),
                tags=analysis_dict.get('tags'),
                result=result,
                file_object=fo_backref,
            )
            session.add(analysis)

    def add_vfp(self, parent_uid: str, child_uid: str, paths: list[str]):
        """Adds a new "virtual file path" for file `child_uid` with path `path` in `parent_uid`"""
        with self.get_read_write_session() as session:
            vfp_list = [
                VirtualFilePath(
                    parent_uid=parent_uid,
                    file_uid=child_uid,
                    file_path=path,
                )
                for path in paths
            ]
            for vfp in vfp_list:
                session.merge(vfp)  # use merge in case paths exist already

    def add_child_to_parent(self, parent_uid: str, child_uid: str):
        with self.get_read_write_session() as session:
            statement = included_files_table.insert().values(parent_uid=parent_uid, child_uid=child_uid)
            with suppress(IntegrityError):
                # entry may already exist, but it is faster trying to create it and failing than checking beforehand
                session.execute(statement)

    # ===== Update / UPDATE =====

    def update_object(self, fw_object: FileObject):
        if isinstance(fw_object, Firmware):
            if not self.is_firmware(fw_object.uid):
                # special case: Trying to upload a file as firmware that is already in the DB as part of another
                # firmware. This is currently not possible and will likely cause errors
                parent_fw = self.get_parent_fw(fw_object.uid)
                raise DbInterfaceError(
                    'Cannot upload file as firmware that is part of another firmware. '
                    f'The file you are trying to upload is already part of the following firmware images: {parent_fw}'
                )
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
            entry = session.get(FileObjectEntry, file_object.uid)
            if entry is None:
                logging.error(f'Trying to update {file_object.uid} but no entry could be found in the DB')
                return
            entry.file_name = file_object.file_name
            entry.depth = file_object.depth
            entry.size = file_object.size
            entry.comments = file_object.comments
            entry.is_firmware = isinstance(file_object, Firmware)
            self._update_parents(file_object.parent_firmware_uids, file_object.parents, entry, session)
            # firmware objects don't have VFPs because they are themselves not contained in another object
            if not isinstance(file_object, Firmware):
                self._update_virtual_file_path(file_object, session)

    @staticmethod
    def _update_virtual_file_path(file_object: FileObject, session: Session):
        for vfp in create_vfp_entries(file_object):
            session.merge(vfp)  # session.merge will insert or update (if it is already in the DB)

    def update_analysis(self, uid: str, plugin: str, analysis_data: dict):
        with self.get_read_write_session() as session:
            entry = session.get(AnalysisEntry, (uid, plugin))
            entry.plugin_version = analysis_data['plugin_version']
            entry.analysis_date = analysis_data['analysis_date']
            entry.summary = analysis_data.get('summary')
            entry.tags = analysis_data.get('tags')
            result = analysis_data.get('result', {})
            if result is not None:
                sanitize(result)
            entry.result = result

    def update_file_object_parents(self, file_uid: str, root_uid: str, parent_uid):
        with self.get_read_write_session() as session:
            fo_entry = session.get(FileObjectEntry, file_uid)
            self._update_parents([root_uid], [parent_uid], fo_entry, session)
