from __future__ import annotations

import re
from typing import Any, NamedTuple

from sqlalchemy import Column, func, select
from sqlalchemy.dialects.postgresql import JSONB

from helperFunctions.data_conversion import get_value_of_first_key
from helperFunctions.tag import TagColor
from helperFunctions.virtual_file_path import get_top_of_virtual_path, get_uids_from_virtual_path
from objects.firmware import Firmware
from storage.db_interface_common import DbInterfaceCommon
from storage.query_conversion import build_generic_search_query, build_query_from_dict, query_parent_firmware
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry, SearchCacheEntry, included_files_table
from web_interface.components.dependency_graph import DepGraphData
from web_interface.file_tree.file_tree import FileTreeData, VirtualPathFileTree
from web_interface.file_tree.file_tree_node import FileTreeNode

RULE_REGEX = re.compile(r'rule\s+([a-zA-Z_]\w*)')


class MetaEntry(NamedTuple):
    uid: str
    hid: str
    tags: dict
    submission_date: int


class CachedQuery(NamedTuple):
    query: str
    yara_rule: str


class FrontEndDbInterface(DbInterfaceCommon):
    def get_last_added_firmwares(self, limit: int = 10) -> list[MetaEntry]:
        with self.get_read_only_session() as session:
            query = select(FirmwareEntry).order_by(FirmwareEntry.submission_date.desc()).limit(limit)
            return [self._get_meta_for_entry(fw_entry) for fw_entry in session.execute(query).scalars()]

    # --- HID ---

    def get_hid(self, uid, root_uid=None) -> str:
        '''
        returns a human-readable identifier (hid) for a given uid
        returns an empty string if uid is not in Database
        '''
        with self.get_read_only_session() as session:
            fo_entry = session.get(FileObjectEntry, uid)
            if fo_entry is None:
                return ''
            if fo_entry.is_firmware:
                return self._get_hid_firmware(fo_entry.firmware)
            return self._get_hid_fo(fo_entry, root_uid)

    @staticmethod
    def _get_hid_firmware(firmware: FirmwareEntry) -> str:
        part = '' if firmware.device_part in ['', None] else f' {firmware.device_part}'
        return f'{firmware.vendor} {firmware.device_name} -{part} {firmware.version} ({firmware.device_class})'

    @staticmethod
    def _get_hid_fo(fo_entry: FileObjectEntry, root_uid: str | None = None) -> str:
        vfp_list = fo_entry.virtual_file_paths.get(root_uid) or get_value_of_first_key(fo_entry.virtual_file_paths)
        return get_top_of_virtual_path(vfp_list[0])

    # --- "nice list" ---

    def get_data_for_nice_list(self, uid_list: list[str], root_uid: str | None) -> list[dict]:
        with self.get_read_only_session() as session:
            mime_dict = self._get_mime_types_for_uid_list(session, uid_list)
            query = select(
                FileObjectEntry.uid, FileObjectEntry.size, FileObjectEntry.file_name, FileObjectEntry.virtual_file_paths
            ).filter(FileObjectEntry.uid.in_(uid_list))
            nice_list_data = [
                {
                    'uid': uid,
                    'size': size,
                    'file_name': file_name,
                    'mime-type': mime_dict.get(uid, 'file-type-plugin/not-run-yet'),
                    'current_virtual_path': self._get_current_vfp(virtual_file_path, root_uid),
                }
                for uid, size, file_name, virtual_file_path in session.execute(query)
            ]
            self._replace_uids_in_nice_list(nice_list_data, root_uid)
            return nice_list_data

    def _replace_uids_in_nice_list(self, nice_list_data: list[dict], root_uid: str):
        uids_in_vfp = set()
        for item in nice_list_data:
            uids_in_vfp.update(uid for vfp in item['current_virtual_path'] for uid in get_uids_from_virtual_path(vfp))
        hid_dict = self._get_hid_dict(uids_in_vfp, root_uid)
        for item in nice_list_data:
            for index, vfp in enumerate(item['current_virtual_path']):
                for uid in get_uids_from_virtual_path(vfp):
                    vfp = vfp.replace(uid, hid_dict.get(uid, uid))
                item['current_virtual_path'][index] = vfp.lstrip('|').replace('|', ' | ')

    def _get_hid_dict(self, uid_set: set[str], root_uid: str) -> dict[str, str]:
        with self.get_read_only_session() as session:
            query = (
                select(FileObjectEntry, FirmwareEntry)
                .outerjoin(FirmwareEntry, FirmwareEntry.uid == FileObjectEntry.uid)
                .filter(FileObjectEntry.uid.in_(uid_set))
            )
            result = {}
            for fo_entry, fw_entry in session.execute(query):
                if fw_entry is None:  # FO
                    result[fo_entry.uid] = self._get_hid_fo(fo_entry, root_uid)
                else:  # FW
                    result[fo_entry.uid] = self._get_hid_firmware(fw_entry)
        return result

    @staticmethod
    def _get_current_vfp(vfp: dict[str, list[str]], root_uid: str) -> list[str]:
        return vfp[root_uid] if root_uid in vfp else get_value_of_first_key(vfp)

    def get_file_name(self, uid: str) -> str:
        with self.get_read_only_session() as session:
            entry = session.get(FileObjectEntry, uid)
            return entry.file_name if entry is not None else 'unknown'

    # --- misc. ---

    def get_firmware_attribute_list(self, attribute: Column) -> list[Any]:
        '''Get all distinct values of an attribute (e.g. all different vendors)'''
        with self.get_read_only_session() as session:
            query = select(attribute).filter(attribute.isnot(None)).distinct()
            return sorted(session.execute(query).scalars())

    def get_device_class_list(self):
        return self.get_firmware_attribute_list(FirmwareEntry.device_class)

    def get_vendor_list(self):
        return self.get_firmware_attribute_list(FirmwareEntry.vendor)

    def get_tag_list(self) -> list[str]:
        with self.get_read_only_session() as session:
            query = select(func.unnest(FirmwareEntry.firmware_tags)).distinct()
            return sorted(session.execute(query).scalars())

    def get_device_name_dict(self):
        device_name_dict = {}
        with self.get_read_only_session() as session:
            query = select(FirmwareEntry.device_class, FirmwareEntry.vendor, FirmwareEntry.device_name)
            for device_class, vendor, device_name in session.execute(query):
                device_name_dict.setdefault(device_class, {}).setdefault(vendor, []).append(device_name)
        return device_name_dict

    def get_other_versions_of_firmware(self, firmware: Firmware) -> list[tuple[str, str]]:
        if not isinstance(firmware, Firmware):
            return []
        with self.get_read_only_session() as session:
            query = (
                select(FirmwareEntry.uid, FirmwareEntry.version)
                .filter(
                    FirmwareEntry.vendor == firmware.vendor,
                    FirmwareEntry.device_name == firmware.device_name,
                    FirmwareEntry.device_part == firmware.part,
                    FirmwareEntry.uid != firmware.uid,
                )
                .order_by(FirmwareEntry.version.asc())
            )
            return list(session.execute(query))

    def get_latest_comments(self, limit=10):
        with self.get_read_only_session() as session:
            subquery = select(FileObjectEntry.uid, func.jsonb_array_elements(FileObjectEntry.comments)).subquery()
            query = select(subquery).order_by(subquery.c.jsonb_array_elements.cast(JSONB)['time'].desc())
            return [{'uid': uid, **comment_dict} for uid, comment_dict in session.execute(query.limit(limit))]

    # --- generic search ---

    def generic_search(
        self,
        search_dict: dict,
        skip: int = 0,
        limit: int = 0,
        only_fo_parent_firmware: bool = False,
        inverted: bool = False,
        as_meta: bool = False,
    ):
        with self.get_read_only_session() as session:
            query = build_generic_search_query(search_dict, only_fo_parent_firmware, inverted)
            query = self._apply_offset_and_limit(query, skip, limit)
            results = session.execute(query).scalars()

            if as_meta:
                return [self._get_meta_for_entry(element) for element in results]
            return [element.uid for element in results]

    def _get_meta_for_entry(self, entry: FirmwareEntry | FileObjectEntry) -> MetaEntry:
        if isinstance(entry, FirmwareEntry):
            return self._get_meta_for_fw(entry)
        if entry.is_firmware:
            return self._get_meta_for_fw(entry.firmware)
        return self._get_meta_for_fo(entry)

    def _get_meta_for_fo(self, entry: FileObjectEntry) -> MetaEntry:
        root_hid = self._get_fo_root_hid(entry)
        tags = {self._get_unpacker_name(entry): TagColor.LIGHT_BLUE}
        return MetaEntry(entry.uid, f'{root_hid}{self._get_hid_fo(entry)}', tags, 0)

    @staticmethod
    def _get_fo_root_hid(entry: FileObjectEntry) -> str:
        for root_fo in entry.root_firmware:
            root_fw = root_fo.firmware
            root_hid = f'{root_fw.vendor} {root_fw.device_name} | '
            break
        else:
            root_hid = ''
        return root_hid

    def _get_meta_for_fw(self, entry: FirmwareEntry) -> MetaEntry:
        hid = self._get_hid_for_fw_entry(entry)
        tags = {
            **{tag: TagColor.GRAY for tag in entry.firmware_tags},
            self._get_unpacker_name(entry): TagColor.LIGHT_BLUE,
        }
        submission_date = entry.submission_date
        return MetaEntry(entry.uid, hid, tags, submission_date)

    @staticmethod
    def _get_hid_for_fw_entry(entry: FirmwareEntry) -> str:
        part = '' if entry.device_part == '' else f' {entry.device_part}'
        return f'{entry.vendor} {entry.device_name} -{part} {entry.version} ({entry.device_class})'

    def _get_unpacker_name(self, fw_entry: FirmwareEntry) -> str:
        unpacker_analysis = self._get_analysis_entry(fw_entry.uid, 'unpacker')
        if unpacker_analysis is None or unpacker_analysis.result is None:
            return 'NOP'
        return unpacker_analysis.result['plugin_used']

    def get_number_of_total_matches(self, search_dict: dict, only_parent_firmwares: bool, inverted: bool) -> int:
        if search_dict == {}:  # if the query is empty: show only firmware on browse DB page
            return self.get_firmware_number()

        if not only_parent_firmwares:
            return self.get_file_object_number(search_dict)

        with self.get_read_only_session() as session:
            query = query_parent_firmware(search_dict, inverted=inverted, count=True)
            return session.execute(query).scalar()

    # --- file tree

    def generate_file_tree_nodes_for_uid_list(
        self, uid_list: list[str], root_uid: str, parent_uid: str | None, whitelist: list[str] | None = None
    ):
        file_tree_data = self.get_file_tree_data(uid_list)
        for entry in file_tree_data:
            yield from self.generate_file_tree_level(entry.uid, root_uid, parent_uid, whitelist, entry)

    def generate_file_tree_level(
        self,
        uid: str,
        root_uid: str,
        parent_uid: str | None = None,
        whitelist: list[str] | None = None,
        data: FileTreeData | None = None,
    ):
        if data is None:
            data = self.get_file_tree_data([uid])[0]
        try:
            yield from VirtualPathFileTree(root_uid, parent_uid, data, whitelist).get_file_tree_nodes()
        except (KeyError, TypeError):  # the file has not been analyzed yet
            yield FileTreeNode(uid, root_uid, not_analyzed=True, name=f'{uid} (not analyzed yet)')

    def get_file_tree_data(self, uid_list: list[str]) -> list[FileTreeData]:
        with self.get_read_only_session() as session:
            # get included files in a separate query because it is way faster than FileObjectEntry.get_included_uids()
            included_files = self._get_included_files_for_uid_list(session, uid_list)
            # get analysis data in a separate query because the analysis may be missing (=> no row in joined result)
            type_analyses = self._get_mime_types_for_uid_list(session, uid_list)
            query = select(
                FileObjectEntry.uid,
                FileObjectEntry.file_name,
                FileObjectEntry.size,
                FileObjectEntry.virtual_file_paths,
            ).filter(FileObjectEntry.uid.in_(uid_list))
            return [
                FileTreeData(uid, file_name, size, vfp, type_analyses.get(uid), included_files.get(uid, set()))
                for uid, file_name, size, vfp in session.execute(query)
            ]

    @staticmethod
    def _get_mime_types_for_uid_list(session, uid_list: list[str]) -> dict[str, str]:
        type_query = (
            select(AnalysisEntry.uid, AnalysisEntry.result['mime'])
            .filter(AnalysisEntry.plugin == 'file_type')
            .filter(AnalysisEntry.uid.in_(uid_list))
        )
        return dict(iter(session.execute(type_query)))

    @staticmethod
    def _get_included_files_for_uid_list(session, uid_list: list[str]) -> dict[str, list[str]]:
        included_query = (
            # aggregation `array_agg()` converts multiple rows to an array
            select(FileObjectEntry.uid, func.array_agg(included_files_table.c.child_uid))
            .filter(FileObjectEntry.uid.in_(uid_list))
            .join(included_files_table, included_files_table.c.parent_uid == FileObjectEntry.uid)
            .group_by(FileObjectEntry)
        )
        return dict(iter(session.execute(included_query)))

    # --- REST ---

    def rest_get_firmware_uids(self, offset: int, limit: int, query: dict = None, recursive=False, inverted=False):
        if query is None:
            query = {}
        if recursive:
            return self.generic_search(query, skip=offset, limit=limit, only_fo_parent_firmware=True, inverted=inverted)
        with self.get_read_only_session() as session:
            db_query = build_query_from_dict(query_dict=query, query=select(FirmwareEntry.uid), fw_only=True)
            db_query = self._apply_offset_and_limit(db_query, offset, limit)
            db_query = db_query.order_by(FirmwareEntry.uid.asc())
            return list(session.execute(db_query).scalars())

    def rest_get_file_object_uids(self, offset: int | None, limit: int | None, query=None) -> list[str]:
        if query:
            return self.generic_search(query, skip=offset, limit=limit)
        with self.get_read_only_session() as session:
            db_query = select(FileObjectEntry.uid)
            db_query = self._apply_offset_and_limit(db_query, offset, limit)
            return list(session.execute(db_query).scalars())

    # --- missing/failed analyses ---

    def find_missing_analyses(self) -> dict[str, set[str]]:
        # FixMe? Query could probably be accomplished more efficiently with left outer join
        missing_analyses = {}
        with self.get_read_only_session() as session:
            fw_query = self._query_all_plugins_of_object(FileObjectEntry.is_firmware.is_(True))
            for fw_uid, fw_plugin_list in session.execute(fw_query):
                fo_query = self._query_all_plugins_of_object(FileObjectEntry.root_firmware.any(uid=fw_uid))
                for fo_uid, fo_plugin_list in session.execute(fo_query):
                    missing_plugins = set(fw_plugin_list) - set(fo_plugin_list)
                    if missing_plugins:
                        missing_analyses.setdefault(fw_uid, set()).add(fo_uid)
        return missing_analyses

    @staticmethod
    def _query_all_plugins_of_object(query_filter):
        return (
            # array_agg() aggregates different values of field into array
            select(AnalysisEntry.uid, func.array_agg(AnalysisEntry.plugin))
            .join(FileObjectEntry, AnalysisEntry.uid == FileObjectEntry.uid)
            .filter(query_filter)
            .group_by(AnalysisEntry.uid)
        )

    def find_failed_analyses(self) -> dict[str, list[str]]:
        result = {}
        with self.get_read_only_session() as session:
            query = select(AnalysisEntry.uid, AnalysisEntry.plugin).filter(
                AnalysisEntry.result.has_key('failed')  # noqa: W601
            )
            for fo_uid, plugin in session.execute(query):
                result.setdefault(plugin, set()).add(fo_uid)
        return result

    # --- search cache ---

    def get_query_from_cache(self, query_id: str) -> CachedQuery | None:
        with self.get_read_only_session() as session:
            entry: SearchCacheEntry = session.get(SearchCacheEntry, query_id)
            if entry is None:
                return None
            return CachedQuery(query=entry.query, yara_rule=entry.yara_rule)

    def get_total_cached_query_count(self):
        with self.get_read_only_session() as session:
            query = select(func.count(SearchCacheEntry.uid))
            return session.execute(query).scalar()

    def search_query_cache(self, offset: int, limit: int):
        with self.get_read_only_session() as session:
            query = select(SearchCacheEntry).offset(offset).limit(limit)
            return [
                (entry.uid, entry.yara_rule, RULE_REGEX.findall(entry.yara_rule))  # FIXME Use a proper yara parser
                for entry in (session.execute(query).scalars())
            ]

    # --- dependency graph ---

    def get_data_for_dependency_graph(self, uid: str) -> list[DepGraphData]:
        fo = self.get_object(uid)
        if fo is None or not fo.files_included:
            return []
        with self.get_read_only_session() as session:
            libraries_by_uid = self._get_elf_analysis_libraries(session, fo.files_included)
            query = (
                select(
                    FileObjectEntry.uid,
                    FileObjectEntry.file_name,
                    FileObjectEntry.virtual_file_paths,
                    AnalysisEntry.result['mime'],
                    AnalysisEntry.result['full'],
                )
                .filter(FileObjectEntry.uid.in_(fo.files_included))
                .join(AnalysisEntry, AnalysisEntry.uid == FileObjectEntry.uid)
                .filter(AnalysisEntry.plugin == 'file_type')
            )
            return [
                DepGraphData(uid, file_name, vfp, mime, full_type, libraries_by_uid.get(uid))
                for uid, file_name, vfp, mime, full_type in session.execute(query)
            ]

    @staticmethod
    def _get_elf_analysis_libraries(session, uid_list: list[str]) -> dict[str, list[str] | None]:
        elf_analysis_query = (
            select(FileObjectEntry.uid, AnalysisEntry.result)
            .filter(FileObjectEntry.uid.in_(uid_list))
            .join(AnalysisEntry, AnalysisEntry.uid == FileObjectEntry.uid)
            .filter(AnalysisEntry.plugin == 'elf_analysis')
        )
        return {
            uid: elf_analysis_result.get('Output', {}).get('libraries', [])
            for uid, elf_analysis_result in session.execute(elf_analysis_query)
            if elf_analysis_result is not None
        }
