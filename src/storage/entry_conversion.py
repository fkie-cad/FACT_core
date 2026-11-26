from __future__ import annotations

import json
from datetime import datetime
from time import time
from typing import Any

from helperFunctions.data_conversion import convert_time_to_str
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_base import DbSerializationError
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry, VirtualFilePath


def firmware_from_entry(fw_entry: FirmwareEntry, analysis_filter: list[str] | None = None) -> Firmware:
    firmware = Firmware.from_uid(uid=fw_entry.uid, file_name=fw_entry.root_object.file_name)
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
    file_object = FileObject.from_uid(uid=fo_entry.uid, file_name=fo_entry.file_name)
    _populate_fo_data(fo_entry, file_object, analysis_filter, included_files, parents, virtual_file_paths, parent_fw)
    return file_object


def _populate_fo_data(
    fo_entry: FileObjectEntry,
    file_object: FileObject,
    analysis_filter: list[str] | None = None,
    included_files: set[str] | None = None,
    parents: set[str] | None = None,
    virtual_file_paths: dict[str, list[str]] | None = None,
    parent_fw: set[str] | None = None,
) -> None:
    file_object.file_name = fo_entry.file_name
    file_object.virtual_file_path = virtual_file_paths or {}
    file_object.processed_analysis = {
        analysis_entry.plugin: analysis_entry_to_dict(analysis_entry)
        for analysis_entry in fo_entry.analyses
        if analysis_filter is None or analysis_entry.plugin in analysis_filter
    }
    file_object.analysis_tags = _collect_analysis_tags(file_object.processed_analysis)
    file_object.comments = fo_entry.comments or []
    file_object.parents = parents or fo_entry.get_parent_uids()
    file_object.files_included = included_files or fo_entry.get_included_uids()
    file_object.parent_firmware_uids = parent_fw or fo_entry.get_parent_fw_uids()


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


_JSON_SCALAR_TYPES = (str, int, float, bool, type(None))
_JSON_CONVERTIBLE_TYPES = (tuple, set, frozenset)


def sanitize(analysis_data: dict) -> dict:
    """
    Makes a Python dict JSON compatible so that it can be stored in the database.
    Keys that are JSON scalar types (int, float, bool, None) are coerced to strings using the same representation that
    json.dumps uses. Tuples, sets and frozensets are not JSON compatible and immutable (i.e. the values cannot be
    sanitized), so they are converted to lists.
    Any other non-JSON-compatible value or key is rejected with a DbSerializationError.
    Null bytes and lone surrogates in strings are handled reversibly by the DB types (SafeJSONB/SafeString), so they
    are not sanitized here.
    """
    for key, value in list(analysis_data.items()):
        new_key = _sanitize_key(analysis_data, key)
        _sanitize_value(analysis_data, new_key, value)

    return analysis_data


def _sanitize_key(analysis_data: dict, key: Any) -> str:  # noqa: ANN401
    if not isinstance(key, _JSON_SCALAR_TYPES):
        raise DbSerializationError(f'key of type {type(key).__name__} is not JSON serializable: {key!r}')
    if isinstance(key, str):
        return key
    str_key = json.dumps(key)  # int/float/bool/None -> '1', '1.5', 'true', 'false', 'null', 'Infinity', 'NaN'
    analysis_data[str_key] = analysis_data.pop(key)
    return str_key


def _sanitize_value(analysis_data: dict, key: str, value: Any) -> None:  # noqa: ANN401
    if isinstance(value, _JSON_CONVERTIBLE_TYPES):
        analysis_data[key] = value = list(value)
    if isinstance(value, dict):
        sanitize(value)
    elif isinstance(value, list):
        sanitize_list(value)
    elif isinstance(value, _JSON_SCALAR_TYPES):
        pass
    else:
        raise DbSerializationError(
            f'value of type {type(value).__name__} for key {key!r} is not JSON serializable: {value!r}'
        )


def sanitize_list(value: list) -> list:
    for index, element in enumerate(list(value)):
        if isinstance(element, _JSON_CONVERTIBLE_TYPES):
            value[index] = element = list(element)  # noqa: PLW2901
        if isinstance(element, dict):
            sanitize(element)
        elif isinstance(element, list):
            sanitize_list(element)
        elif isinstance(element, _JSON_SCALAR_TYPES):
            pass
        else:
            raise DbSerializationError(
                f'value of type {type(element).__name__} in list is not JSON serializable: {element!r}'
            )
    return value


def create_analysis_entries(file_object: FileObject, fo_backref: FileObjectEntry) -> list[AnalysisEntry]:
    return [
        AnalysisEntry(
            uid=file_object.uid,
            plugin=plugin_name,
            plugin_version=analysis_data.get('plugin_version'),
            system_version=analysis_data.get('system_version'),
            analysis_date=analysis_data.get('analysis_date'),
            summary=sanitize_list(analysis_data.get('summary', [])),
            tags=sanitize(analysis_data.get('tags') or {}),
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
