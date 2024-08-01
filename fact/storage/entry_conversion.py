from __future__ import annotations

import logging
from datetime import datetime
from time import time

from helperFunctions.data_conversion import convert_time_to_str
from objects.file import FileObject
from objects.firmware import Firmware
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry, VirtualFilePath


def firmware_from_entry(fw_entry: FirmwareEntry, analysis_filter: list[str] | None = None) -> Firmware:
    firmware = Firmware()
    _populate_fo_data(fw_entry.root_object, firmware, analysis_filter, parent_fw=set())
    firmware.device_name = fw_entry.device_name
    firmware.device_class = fw_entry.device_class
    firmware.release_date = convert_time_to_str(fw_entry.release_date)
    firmware.vendor = fw_entry.vendor
    firmware.version = fw_entry.version
    firmware.part = fw_entry.device_part
    firmware.tags = {tag: 'secondary' for tag in getattr(fw_entry, 'firmware_tags', [])}
    return firmware


def file_object_from_entry(
    fo_entry: FileObjectEntry,
    analysis_filter: list[str] | None = None,
    included_files: set[str] | None = None,
    parents: set[str] | None = None,
    virtual_file_paths: dict[str, list[str]] | None = None,
    parent_fw: set[str] | None = None,
) -> FileObject:
    file_object = FileObject()
    _populate_fo_data(fo_entry, file_object, analysis_filter, included_files, parents, virtual_file_paths, parent_fw)
    return file_object


def _convert_vfp_entries_to_dict(vfp_list: list[VirtualFilePath]) -> dict[str, list[str]]:
    result = {}
    for vfp_entry in vfp_list or []:
        result.setdefault(vfp_entry.parent_uid, []).append(vfp_entry.file_path)
    return result


def _populate_fo_data(
    fo_entry: FileObjectEntry,
    file_object: FileObject,
    analysis_filter: list[str] | None = None,
    included_files: set[str] | None = None,
    parents: set[str] | None = None,
    virtual_file_paths: dict[str, list[str]] | None = None,
    parent_fw: set[str] | None = None,
):
    file_object.uid = fo_entry.uid
    file_object.size = fo_entry.size
    file_object.file_name = fo_entry.file_name
    file_object.virtual_file_path = virtual_file_paths or {}
    file_object.processed_analysis = {
        analysis_entry.plugin: analysis_entry_to_dict(analysis_entry)
        for analysis_entry in fo_entry.analyses
        if analysis_filter is None or analysis_entry.plugin in analysis_filter
    }
    file_object.analysis_tags = _collect_analysis_tags(file_object.processed_analysis)
    file_object.comments = fo_entry.comments
    file_object.parents = fo_entry.get_parent_uids() if parents is None else parents
    file_object.files_included = fo_entry.get_included_uids() if included_files is None else included_files
    file_object.parent_firmware_uids = fo_entry.get_parent_fw_uids() if parent_fw is None else parent_fw


def _collect_analysis_tags(analysis_dict: dict) -> dict:
    return {plugin: plugin_data['tags'] for plugin, plugin_data in analysis_dict.items() if 'tags' in plugin_data}


def create_firmware_entry(firmware: Firmware, fo_entry: FileObjectEntry) -> FirmwareEntry:
    return FirmwareEntry(
        uid=firmware.uid,
        submission_date=time(),
        release_date=datetime.strptime(firmware.release_date, '%Y-%m-%d'),
        version=firmware.version,
        vendor=firmware.vendor,
        device_name=firmware.device_name,
        device_class=firmware.device_class,
        device_part=firmware.part,
        firmware_tags=firmware.tags,
        root_object=fo_entry,
    )


def create_vfp_entries(file_object: FileObject) -> list[VirtualFilePath]:
    return [
        VirtualFilePath(
            parent_uid=parent_uid,
            file_uid=file_object.uid,
            file_path=path,
        )
        for parent_uid, path_list in file_object.virtual_file_path.items()
        for path in path_list
    ]


def create_file_object_entry(file_object: FileObject) -> FileObjectEntry:
    sanitize(file_object.virtual_file_path)
    return FileObjectEntry(
        uid=file_object.uid,
        sha256=file_object.sha256,
        file_name=file_object.file_name,
        root_firmware=[],
        parent_files=[],
        included_files=[],
        depth=file_object.depth,
        size=file_object.size,
        comments=file_object.comments,
        is_firmware=isinstance(file_object, Firmware),
        firmware=None,
        analyses=[],
    )


def sanitize(analysis_data: dict) -> dict:
    """Null bytes are not legal in PostgreSQL JSON columns -> remove them"""
    for key, value in list(analysis_data.items()):
        _sanitize_value(analysis_data, key, value)
        _sanitize_key(analysis_data, key)

    return analysis_data


def _sanitize_value(analysis_data: dict, key: str, value):
    if isinstance(value, dict):
        sanitize(value)
    elif isinstance(value, str):
        analysis_data[key] = _sanitize_string(value)
    elif isinstance(value, list):
        _sanitize_list(value)
    elif isinstance(value, bytes):
        logging.warning(
            f'Plugin result contains bytes entry. '
            f'Plugin results should only contain JSON compatible data structures!:\n\t{value!r}'
        )
        analysis_data[key] = value.decode(errors='replace')


def _sanitize_string(string: str) -> str:
    string = string.replace('\0', '')
    try:
        string.encode()
    except UnicodeEncodeError:
        string = string.encode(errors='replace').decode()
    return string


def _sanitize_key(analysis_data: dict, key: str):
    if '\0' in key:
        analysis_data[key.replace('\0', '')] = analysis_data.pop(key)


def _sanitize_list(value: list) -> list:
    for index, element in enumerate(value):
        if isinstance(element, dict):
            sanitize(element)
        elif isinstance(element, str):
            value[index] = _sanitize_string(element)
    return value


def create_analysis_entries(file_object: FileObject, fo_backref: FileObjectEntry) -> list[AnalysisEntry]:
    return [
        AnalysisEntry(
            uid=file_object.uid,
            plugin=plugin_name,
            plugin_version=analysis_data.get('plugin_version'),
            system_version=analysis_data.get('system_version'),
            analysis_date=analysis_data.get('analysis_date'),
            summary=_sanitize_list(analysis_data.get('summary', [])),
            tags=analysis_data.get('tags'),
            result=sanitize(analysis_data.get('result', {})),
            file_object=fo_backref,
        )
        for plugin_name, analysis_data in file_object.processed_analysis.items()
    ]


def analysis_entry_to_dict(entry: AnalysisEntry) -> dict:
    return {
        'analysis_date': entry.analysis_date,
        'plugin_version': entry.plugin_version,
        'system_version': entry.system_version,
        'summary': entry.summary or [],
        'tags': entry.tags or {},
        'result': entry.result or {},
    }
