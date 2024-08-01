from fact.objects.file import FileObject
from fact.objects.firmware import Firmware


def _add_firmware_only_fields(fo, meta):
    """
    Adds fields relevant for :class:`objects.firmware.Firmware` objects from
    `fo` to `meta`

    :param meta: The dictionary to add the fields to
    :param fo: A :class:`objects.firmware.Firmware`
    """
    if isinstance(fo, Firmware):
        fo.root_uid = fo.uid
        meta['device_name'] = fo.device_name
        meta['device_class'] = fo.device_class
        meta['device_part'] = fo.part
        meta['vendor'] = fo.vendor
        meta['version'] = fo.version
        meta['release_date'] = fo.release_date


def _add_file_object_only_fields(fo, meta):
    """
    Adds fields relevant for only :class:`objects.file.FileObject` but not
    Firmware objects from `fo` to `meta`

    :param meta: The dictionary to add the fields to
    :param fo: A :class:`objects.firmware.FileObject`
    """
    if not isinstance(fo, Firmware):
        meta['firmwares_including_this_file'] = list(fo.parent_firmware_uids)
        meta['virtual_file_path'] = fo.virtual_file_path


def _add_general_information(fo, meta):
    """
    Adds fields relevant for :class:`objects.file.FileObjects` and
    :class:`objects.firmware.Firmware` from `fo` to `meta`

    :param meta: The dictionary to add the fields to
    :param fo: A :class:`objects.file.FileObject`
    """
    meta['hid'] = fo.get_hid()
    meta['size'] = fo.size
    meta['number_of_included_files'] = len(fo.files_included) if fo.files_included else 0
    meta['included_files'] = list(fo.files_included) if fo.files_included else []
    meta['total_files_in_firmware'] = len(fo.list_of_all_included_files) if fo.list_of_all_included_files else 'unknown'


def create_meta_dict(fo: FileObject):
    """
    Creates a dictionary with the meta information contained in :class:`objects.file.FileObject` `fo`
    """
    meta = {}
    _add_firmware_only_fields(fo, meta)
    _add_file_object_only_fields(fo, meta)
    _add_general_information(fo, meta)
    return meta
