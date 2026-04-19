from __future__ import annotations

import logging
from operator import or_
from typing import TYPE_CHECKING, Dict, Iterable, List

from sqlalchemy import distinct, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import NoResultFound

from objects.firmware import Firmware
from storage.db_interface_base import ReadOnlyDbInterface
from storage.entry_conversion import analysis_entry_to_dict, file_object_from_entry, firmware_from_entry
from storage.query_conversion import build_query_from_dict
from storage.schema import (
    AnalysisEntry,
    FileObjectEntry,
    FirmwareEntry,
    VirtualFilePath,
    fw_files_table,
    included_files_table,
)

if TYPE_CHECKING:
    from sqlalchemy.sql import Select

    from objects.file import FileObject

PLUGINS_WITH_TAG_PROPAGATION = [  # FIXME This should be inferred in a sensible way. This is not possible yet.
    'crypto_material',
    'cve_lookup',
    'known_vulnerabilities',
    'qemu_exec',
    'software_components',
    'users_and_passwords',
]
Summary = Dict[str, List[str]]


class DbInterfaceCommon(ReadOnlyDbInterface):
    def exists(self, uid: str) -> bool:
        with self.get_read_only_session() as session:
            query = select(FileObjectEntry.uid).filter(FileObjectEntry.uid == uid)
            return bool(session.execute(query).scalar())

    def uid_list_exists(self, uid_list: list[str] | set[str]) -> set:
        """Check for a list of UIDs if DB entries exist. Returns a set of UIDs with existing DB entries."""
        with self.get_read_only_session() as session:
            query = select(FileObjectEntry.uid).filter(FileObjectEntry.uid.in_(uid_list))
            return set(session.execute(query).scalars())

    def is_firmware(self, uid: str) -> bool:
        with self.get_read_only_session() as session:
            query = select(FirmwareEntry.uid).filter(FirmwareEntry.uid == uid)
            return bool(session.execute(query).scalar())

    def all_uids_found_in_database(self, uid_list: list[str]) -> bool:
        if not uid_list:
            return True
        with self.get_read_only_session() as session:
            query = select(func.count(FileObjectEntry.uid)).filter(FileObjectEntry.uid.in_(uid_list))
            return session.execute(query).scalar() >= len(uid_list)

    # ===== Read / SELECT =====

    def get_object(self, uid: str, analysis_filter: list[str] | None = None) -> FileObject | Firmware | None:
        if self.is_firmware(uid):
            return self.get_firmware(uid, analysis_filter=analysis_filter)
        return self.get_file_object(uid, analysis_filter=analysis_filter)

    def get_firmware(self, uid: str, analysis_filter: list[str] | None = None) -> Firmware | None:
        with self.get_read_only_session() as session:
            fw_entry = session.get(FirmwareEntry, uid)
            if fw_entry is None:
                return None
            return self._firmware_from_entry(fw_entry, analysis_filter=analysis_filter)

    def _firmware_from_entry(self, fw_entry: FirmwareEntry, analysis_filter: list[str] | None = None) -> Firmware:
        firmware = firmware_from_entry(fw_entry, analysis_filter)
        firmware.analysis_tags = self._collect_analysis_tags_from_children(firmware.uid)
        return firmware

    def get_file_object(self, uid: str, analysis_filter: list[str] | None = None) -> FileObject | None:
        with self.get_read_only_session() as session:
            fo_entry = session.get(FileObjectEntry, uid)
            if fo_entry is None:
                return None
            return file_object_from_entry(
                fo_entry,
                analysis_filter=analysis_filter,
                virtual_file_paths=self.get_vfps(uid),
                parent_fw=self.get_parent_fw(uid),
            )

    def get_parent_fw_for_uid_list(self, uid_list: list[str]) -> dict[str, set[str]]:
        with self.get_read_only_session() as session:
            query = (
                select(fw_files_table.c.file_uid, func.array_agg(fw_files_table.c.root_uid))
                .filter(fw_files_table.c.file_uid.in_(uid_list))
                .group_by(fw_files_table.c.file_uid)
            )
            return {uid: set(parent_uid_list) for uid, parent_uid_list in session.execute(query)}

    def get_parent_fw(self, uid: str) -> set[str]:
        return self.get_parent_fw_for_uid_list([uid]).get(uid, set())

    def get_objects_by_uid_list(
        self, uid_list: list[str] | set[str], analysis_filter: list[str] | None = None
    ) -> list[FileObject]:
        with self.get_read_only_session() as session:
            parents_table = aliased(included_files_table, name='parents')
            children_table = aliased(included_files_table, name='children')
            query = (
                select(
                    FileObjectEntry,
                    func.array_agg(parents_table.c.child_uid),
                    func.array_agg(children_table.c.parent_uid),
                )
                .filter(FileObjectEntry.uid.in_(uid_list))
                # outer join here because objects may not have included files
                .outerjoin(parents_table, parents_table.c.parent_uid == FileObjectEntry.uid)
                .join(children_table, children_table.c.child_uid == FileObjectEntry.uid)
                .group_by(FileObjectEntry)
            )
            virtual_file_paths = self.get_vfps_for_uid_list(uid_list)
            parent_fw = self.get_parent_fw_for_uid_list(uid_list)
            file_objects = [
                file_object_from_entry(
                    fo_entry,
                    analysis_filter,
                    included_files={f for f in included_files if f},
                    parents=set(parents),
                    virtual_file_paths=virtual_file_paths[fo_entry.uid],
                    parent_fw=parent_fw.get(fo_entry.uid, set()),
                )
                for fo_entry, included_files, parents in session.execute(query)
            ]
            fw_query = select(FirmwareEntry).filter(FirmwareEntry.uid.in_(uid_list))
            firmware = [self._firmware_from_entry(fw_entry) for fw_entry in session.execute(fw_query).scalars()]
            return file_objects + firmware

    def _get_analysis_entry(self, uid: str, plugin: str) -> AnalysisEntry | None:
        with self.get_read_only_session() as session:
            try:
                query = select(AnalysisEntry).filter_by(uid=uid, plugin=plugin)
                return session.execute(query).scalars().one()
            except NoResultFound:
                return None

    def get_analysis(self, uid: str, plugin: str) -> dict | None:
        entry = self._get_analysis_entry(uid, plugin)
        if entry is None:
            return None
        return analysis_entry_to_dict(entry)

    def get_vfps(self, uid: str, parent_uid: str | None = None, root_uid: str | None = None) -> dict[str, list[str]]:
        """
        Get all virtual file paths of file with UID `uid` in all parent files. If `parent_uid` is set, returns only the
        paths in this parent file. If `root_uid` is set, return only the paths inside the firmware with UID root_uid.
        """
        with self.get_read_only_session() as session:
            query = select(VirtualFilePath.parent_uid, VirtualFilePath.file_path).filter(
                VirtualFilePath.file_uid == uid
            )
            if parent_uid is not None:
                query = query.filter(VirtualFilePath.parent_uid == parent_uid)
            if root_uid is not None:
                query = query.outerjoin(fw_files_table, fw_files_table.c.file_uid == VirtualFilePath.parent_uid).filter(
                    or_(fw_files_table.c.root_uid == root_uid, VirtualFilePath.parent_uid == root_uid)
                )
            result = {}
            for parent, path in session.execute(query) or []:
                result.setdefault(parent, []).append(path)
            return result

    def get_vfps_for_uid_list(
        self, uid_list: list[str] | set[str], root_uid: str | None = None
    ) -> dict[str, dict[str, list[str]]]:
        """
        Gets all virtual file paths (see `get_vfps()`) for a list of UIDs. Returns a dictionary with key=uid and
        value=vfp_dict for that file (vfp_dict is the same as the output of `get_vfps()` for that file). If `root_uid`
        is set, only return the paths inside the firmware with UID `root_uid`.
        """
        if not uid_list:
            return {}
        with self.get_read_only_session() as session:
            query = select(VirtualFilePath).filter(VirtualFilePath.file_uid.in_(uid_list))
            if root_uid:
                query = query.outerjoin(fw_files_table, fw_files_table.c.file_uid == VirtualFilePath.parent_uid)
                query = query.filter(
                    or_(
                        fw_files_table.c.root_uid == root_uid,  # we only want the parents that are in root
                        VirtualFilePath.parent_uid == root_uid,  # or parent == root (no entry in fw_files_table then)
                    )
                )
            result = {}
            for vfp in session.execute(query).scalars() or []:  # type: VirtualFilePath
                result.setdefault(vfp.file_uid, {}).setdefault(vfp.parent_uid, []).append(vfp.file_path)
            return result

    def get_vfps_in_parent(self, parent_uid: str) -> dict[str, list[str]]:
        """Get all virtual file paths (see `get_vfps()`) for files inside a container with UID `parent_uid`."""
        with self.get_read_only_session() as session:
            query = select(VirtualFilePath.file_uid, VirtualFilePath.file_path).filter(
                VirtualFilePath.parent_uid == parent_uid
            )
            result = {}
            for uid, path in session.execute(query):
                result.setdefault(uid, []).append(path)
            return result

    def get_file_tree_path(self, uid: str, root_uid: str | None = None) -> list[list[str]]:
        return self.get_file_tree_path_for_uid_list([uid], root_uid=root_uid).get(uid, [])

    def get_file_tree_path_for_uid_list(
        self, uid_list: Iterable[str], root_uid: str | None = None
    ) -> dict[str, list[list[str]]]:
        """
        Generate all file paths for a list of UIDs `uid_list`. A path is a list of UIDs representing the path from root
        (firmware) to the file in the file tree (with root having index 0 and so on).
        result: {
            "uid_1": [
                ["root_uid", ..., "parent_uid", "uid_1"], ...
            ], ...
        }
        if `root_uid` is set, include only the paths that start with root_uid.
        """
        with self.get_read_only_session() as session:
            top_query = (
                select(included_files_table)
                .filter(included_files_table.c.child_uid.in_(uid_list))
                .cte(recursive=True)  # this makes the query recursive
            )
            child = aliased(top_query)
            parent = aliased(included_files_table)
            bottom_query = select(
                top_query.union_all(select(parent).join(child, parent.c.child_uid == child.c.parent_uid))
            )
            path_dict = self._convert_tuples_to_path(session.execute(bottom_query) or [], uid_list)

            for uid, path_list in path_dict.items():
                if not path_list:
                    # if this is a FW/root object, there is no path data => use [[uid]] as fallback
                    path_list.append([uid])

            if root_uid is not None:
                self._remove_paths_lacking_root_uid(path_dict, root_uid)
            return path_dict

    @staticmethod
    def _remove_paths_lacking_root_uid(path_dict: dict[str, list[list[str]]], root_uid: str):
        # remove the paths that don't start with root_uid
        for path_list in path_dict.values():
            for uid_list in path_list[:]:
                if uid_list[0] != root_uid:
                    path_list.remove(uid_list)
        # remove the UIDs where the path lists are now empty
        for uid, path_list in list(path_dict.items()):
            if not path_list:
                path_dict.pop(uid)

    def _convert_tuples_to_path(
        self, parent_child_pairs: Iterable[tuple[str, str]], uid_list: list[str]
    ) -> dict[str, list[list[str]]]:
        child_to_parents = {}
        for parent, child in parent_child_pairs:
            child_to_parents.setdefault(child, set()).add(parent)
        return {uid: self._generate_file_tree_path(uid, child_to_parents) for uid in uid_list}

    def _generate_file_tree_path(self, uid: str, child_to_parents: dict[str, set[str]]) -> list[list[str]]:
        """
        Combines all child-parent relations in the `child_to_parents` dict into a list of paths (as uid list) from `uid`
        to roots (FW uids) through the file tree.
        """
        return [
            [*path, uid]
            for parent in child_to_parents.get(uid, [])
            for path in (
                self._generate_file_tree_path(parent, child_to_parents) if parent in child_to_parents else [[parent]]
            )
        ]

    # ===== included files. =====

    def get_list_of_all_included_files(self, fo: FileObject) -> set[str]:
        if isinstance(fo, Firmware):
            return self.get_all_files_in_fw(fo.uid)
        return self.get_all_files_in_fo(fo)

    def get_all_files_in_fw(self, fw_uid: str) -> set[str]:
        """Get a set of UIDs of all files (recursively) contained in a firmware"""
        with self.get_read_only_session() as session:
            query = select(fw_files_table.c.file_uid).where(fw_files_table.c.root_uid == fw_uid)
            return set(session.execute(query).scalars())

    def get_all_files_in_fo(self, fo: FileObject) -> set[str]:
        """Get a set of UIDs of all files (recursively) contained in a file"""
        with self.get_read_only_session() as session:
            return self._get_files_in_files(session, fo.files_included).union({fo.uid, *fo.files_included})

    def _get_files_in_files(self, session, uid_set: set[str], recursive: bool = True) -> set[str]:
        if not uid_set:
            return set()
        query = select(FileObjectEntry).filter(FileObjectEntry.uid.in_(uid_set))
        included_files = {child.uid for fo in session.execute(query).scalars() for child in fo.included_files}
        if recursive and included_files:
            included_files.update(self._get_files_in_files(session, included_files))
        return included_files

    # ===== summary =====

    def get_complete_object_including_all_summaries(self, uid: str) -> FileObject:
        """
        input uid
        output:
            like get_object, but includes all summaries and list of all included files set
        """
        fo = self.get_object(uid)
        if fo is None:
            raise Exception(f'UID not found: {uid}')
        fo.list_of_all_included_files = self.get_list_of_all_included_files(fo)
        for plugin, analysis_result in fo.processed_analysis.items():
            analysis_result['summary'] = self.get_summary(fo, plugin)
        return fo

    def get_summary(self, fo: FileObject, selected_analysis: str) -> Summary | None:
        if selected_analysis not in fo.processed_analysis:
            logging.warning(f'Analysis {selected_analysis} not available on {fo.uid}')
            return None
        if 'summary' not in fo.processed_analysis[selected_analysis]:
            return None
        if not isinstance(fo, Firmware):
            included_files = fo.list_of_all_included_files or self.get_list_of_all_included_files(fo)
        else:
            included_files = self.get_all_files_in_fw(fo.uid).union({fo.uid})
        return self._collect_summary_for_uid_list(included_files, selected_analysis)

    def _collect_summary_for_uid_list(self, uid_list: set[str] | list[str], plugin: str) -> Summary:
        with self.get_read_only_session() as session:
            query = select(AnalysisEntry.uid, AnalysisEntry.summary).filter(
                AnalysisEntry.plugin == plugin, AnalysisEntry.uid.in_(uid_list)
            )
            summary = {}
            for uid, summary_list in session.execute(query):  # type: str, list[str]
                for item in set(summary_list or []):
                    summary.setdefault(item, []).append(uid)
        return summary

    # ===== tags =====

    def _collect_analysis_tags_from_children(self, uid: str) -> dict:
        unique_tags = {}
        with self.get_read_only_session() as session:
            query = (
                select(FileObjectEntry.uid, AnalysisEntry.plugin, AnalysisEntry.tags)
                .filter(FileObjectEntry.root_firmware.any(uid=uid))
                .join(AnalysisEntry, FileObjectEntry.uid == AnalysisEntry.uid)
                .filter(AnalysisEntry.tags != JSONB.NULL, AnalysisEntry.plugin.in_(PLUGINS_WITH_TAG_PROPAGATION))
            )
            for _, plugin_name, tags in session.execute(query):
                for tag_type, tag in tags.items():
                    if tag_type == 'root_uid' or not tag['propagate']:
                        continue
                    unique_tags.setdefault(plugin_name, {})
                    if tag_type in unique_tags[plugin_name] and tag not in unique_tags[plugin_name].values():
                        key = f'{tag_type}-{len(unique_tags[plugin_name])}'
                    else:
                        key = tag_type
                    unique_tags[plugin_name][key] = tag
        return unique_tags

    # ===== misc. =====

    def get_firmware_number(self, query: dict | None = None) -> int:
        with self.get_read_only_session() as session:
            db_query = select(func.count(FirmwareEntry.uid))
            if query:
                db_query = build_query_from_dict(query_dict=query, query=db_query, fw_only=True)
            return session.execute(db_query).scalar()

    def get_file_object_number(self, query: dict, zero_on_empty_query: bool = True) -> int:
        if zero_on_empty_query and query == {}:
            return 0
        with self.get_read_only_session() as session:
            query = build_query_from_dict(query, query=select(func.count(distinct(FileObjectEntry.uid))))
            return session.execute(query).scalar()

    @staticmethod
    def _apply_offset_and_limit(query: Select, skip: int | None, limit: int | None) -> Select:
        if skip:
            query = query.offset(skip)
        if limit:
            query = query.limit(limit)
        return query
