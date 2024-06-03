from __future__ import annotations

from typing import TYPE_CHECKING, Any

from objects.firmware import Firmware

if TYPE_CHECKING:
    from objects.file import FileObject


def _get_firmware_only_fields(fo: Firmware) -> dict[str, Any]:
    """
    Get fields relevant for :class:`objects.firmware.Firmware` objects from `fo`

    :param fo: A :class:`objects.firmware.Firmware`
    """
    return {
        'device_name': fo.device_name,
        'device_class': fo.device_class,
        'device_part': fo.part,
        'vendor': fo.vendor,
        'version': fo.version,
        'release_date': fo.release_date,
    }


def _get_file_object_only_fields(fo: FileObject) -> dict[str, Any]:
    """
    Get fields relevant for only :class:`objects.file.FileObject` but not Firmware objects from `fo`

    :param fo: A :class:`objects.firmware.FileObject`
    """
    return {
        'firmwares_including_this_file': list(fo.parent_firmware_uids),
        'virtual_file_path': fo.virtual_file_path,
    }


def _get_general_information(fo: FileObject) -> dict[str, Any]:
    """
    Get fields relevant for :class:`objects.file.FileObjects` and :class:`objects.firmware.Firmware` from `fo`

    :param fo: A :class:`objects.file.FileObject`
    """
    return {
        'hid': fo.get_hid(),
        'size': fo.size,
        'number_of_included_files': len(fo.files_included) if fo.files_included else 0,
        'included_files': list(fo.files_included) if fo.files_included else [],
        'total_files_in_firmware': len(fo.list_of_all_included_files) if fo.list_of_all_included_files else 'unknown',
    }


def create_meta_dict(fo: FileObject) -> dict[str, Any]:
    """
    Creates a dictionary with the meta information contained in :class:`objects.file.FileObject` `fo`
    """
    meta: dict[str, Any] = _get_general_information(fo)
    if not isinstance(fo, Firmware):
        meta.update(_get_file_object_only_fields(fo))
    else:
        meta.update(_get_firmware_only_fields(fo))
    return meta
