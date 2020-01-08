from objects.firmware import Firmware


def _add_firmware_exclusive_information(fo, meta):
    if isinstance(fo, Firmware):
        fo.root_uid = fo.uid
        meta['device_name'] = fo.device_name
        meta['device_class'] = fo.device_class
        meta['device_part'] = fo.part
        meta['vendor'] = fo.vendor
        meta['version'] = fo.version
        meta['release_date'] = fo.release_date


def _add_file_object_exclusive_information(fo, meta):
    if not isinstance(fo, Firmware):
        meta['firmwares_including_this_file'] = list(fo.get_virtual_file_paths().keys())
        meta['virtual_file_path'] = fo.get_virtual_paths_for_one_uid()


def _add_general_information(fo, meta):
    meta['hid'] = fo.get_hid()
    meta['size'] = fo.size
    if isinstance(fo.list_of_all_included_files, list):
        meta['number_of_files'] = len(fo.list_of_all_included_files)


def create_meta_dict(fo):
    meta = {}
    _add_firmware_exclusive_information(fo, meta)
    _add_file_object_exclusive_information(fo, meta)
    _add_general_information(fo, meta)
    return meta
