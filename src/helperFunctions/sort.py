
def sort_nice_data_list_by_virtual_path(fo_list, root_uid=None):
    if root_uid is not None:
        set_root_uids(fo_list, root_uid)
    sorted_list = sorted(fo_list, key=lambda k: k['virtual_file_paths'][0])
    return sorted_list


def _get_virtual_path_of_file(fo):
    if fo is None:
        return ""
    else:
        return fo.get_virtual_paths_for_one_uid()[0]


def set_root_uids(fo_list, root_uid):
    for item in fo_list:
        if item is not None:
            item["root_uid"] = root_uid
