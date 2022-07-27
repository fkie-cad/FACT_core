from datetime import datetime
from time import time
from typing import List, Optional, Set

from helperFunctions.data_conversion import convert_time_to_str
from objects.file import FileObject
from objects.firmware import Firmware
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry

META_KEYS = {'tags', 'summary', 'analysis_date', 'plugin_version', 'system_version', 'file_system_flag'}


def firmware_from_entry(fw_entry: FirmwareEntry, analysis_filter: Optional[List[str]] = None) -> Firmware:
    firmware = Firmware()
    _populate_fo_data(fw_entry.root_object, firmware, analysis_filter)
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
    analysis_filter: Optional[List[str]] = None,
    included_files: Optional[Set[str]] = None,
    parents: Optional[Set[str]] = None,
) -> FileObject:
    file_object = FileObject()
    _populate_fo_data(fo_entry, file_object, analysis_filter, included_files, parents)
    return file_object


def _populate_fo_data(
    fo_entry: FileObjectEntry,
    file_object: FileObject,
    analysis_filter: Optional[List[str]] = None,
    included_files: Optional[Set[str]] = None,
    parents: Optional[Set[str]] = None,
):
    file_object.uid = fo_entry.uid
    file_object.size = fo_entry.size
    file_object.file_name = fo_entry.file_name
    file_object.virtual_file_path = fo_entry.virtual_file_paths
    file_object.processed_analysis = {
        analysis_entry.plugin: analysis_entry_to_dict(analysis_entry)
        for analysis_entry in fo_entry.analyses
        if analysis_filter is None or analysis_entry.plugin in analysis_filter
    }
    file_object.analysis_tags = _collect_analysis_tags(file_object.processed_analysis)
    file_object.comments = fo_entry.comments
    file_object.parents = fo_entry.get_parent_uids() if parents is None else parents
    file_object.files_included = fo_entry.get_included_uids() if included_files is None else included_files
    file_object.parent_firmware_uids = set(file_object.virtual_file_path)


def _collect_analysis_tags(analysis_dict: dict) -> dict:
    return {
        plugin: plugin_data['tags']
        for plugin, plugin_data in analysis_dict.items()
        if 'tags' in plugin_data
    }


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


def get_analysis_without_meta(analysis_data: dict) -> dict:
    analysis_without_meta = {
        key: value
        for key, value in analysis_data.items()
        if key not in META_KEYS
    }
    sanitize(analysis_without_meta)
    return analysis_without_meta


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
        virtual_file_paths=file_object.virtual_file_path,
        is_firmware=isinstance(file_object, Firmware),
        firmware=None,
        analyses=[],
    )


def sanitize(analysis_data):
    '''Null bytes are not legal in PostgreSQL JSON columns -> remove them'''
    for key, value in analysis_data.items():
        if isinstance(value, dict):
            sanitize(value)
        elif isinstance(value, str) and '\0' in value:
            analysis_data[key] = value.replace('\0', '')
        elif isinstance(value, list):
            _sanitize_list(value)


def _sanitize_list(value: list):
    for index, element in enumerate(value):
        if isinstance(element, dict):
            sanitize(element)
        elif isinstance(element, str) and '\0' in element:
            value[index] = element.replace('\0', '')


def create_analysis_entries(file_object: FileObject, fo_backref: FileObjectEntry) -> List[AnalysisEntry]:
    return [
        AnalysisEntry(
            uid=file_object.uid,
            plugin=plugin_name,
            plugin_version=analysis_data.get('plugin_version'),
            system_version=analysis_data.get('system_version'),
            analysis_date=analysis_data.get('analysis_date'),
            summary=analysis_data.get('summary'),
            tags=analysis_data.get('tags'),
            result=get_analysis_without_meta(analysis_data),
            file_object=fo_backref,
        )
        for plugin_name, analysis_data in file_object.processed_analysis.items()
    ]


def analysis_entry_to_dict(entry: AnalysisEntry) -> dict:
    return {
        'analysis_date': entry.analysis_date,
        'plugin_version': entry.plugin_version,
        'system_version': entry.system_version,
        'summary': entry.summary,
        'tags': entry.tags or {},
        **entry.result,
    }
