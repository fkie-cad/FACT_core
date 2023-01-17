from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid circular import
    from objects.file import FileObject


def split_virtual_path(virtual_path: str) -> list[str]:
    return [element for element in virtual_path.split('|') if element]


def join_virtual_path(*elements: str) -> str:
    return '|'.join(elements)


def get_base_of_virtual_path(virtual_path: str) -> str:
    return join_virtual_path(*split_virtual_path(virtual_path)[:-1])


def get_top_of_virtual_path(virtual_path: str) -> str:
    return split_virtual_path(virtual_path)[-1] if virtual_path else ''


def merge_vfp_lists(old_vfp_list: list[str], new_vfp_list: list[str]) -> list[str]:
    '''
    virtual file paths (VFPs) with the same base are updated and should be replaced
    VFPs with different bases correspond to different archives in the firmware and should be kept
    '''
    old_vfp_by_base = _split_vfp_list_by_base(old_vfp_list)
    new_vfp_by_base = _split_vfp_list_by_base(new_vfp_list)
    for base in new_vfp_by_base:
        old_vfp_by_base[base] = new_vfp_by_base[base]
    return [vfp for vfp_list in old_vfp_by_base.values() for vfp in vfp_list]


def _split_vfp_list_by_base(vfp_list: list[str]) -> dict[str, list[str]]:
    '''
    for virtual file path (VFP) list ['uid|/dir/file', 'uid|/file2', 'uid|other_uid|/file3']
    the result would be {'uid': ['uid|/dir/file', 'uid|/file2'], 'uid|other_uid': ['uid|other_uid|/file3']}
    '''
    vfp_list_by_base = {}
    for path in vfp_list:
        vfp_list_by_base.setdefault(get_base_of_virtual_path(path), []).append(path)
    return vfp_list_by_base


def get_parent_uids_from_virtual_path(file_object: 'FileObject') -> set[str]:
    '''
    Get the UIDs of parent files (aka files with include this file) from the virtual file paths of a FileObject.

    :param file_object: The FileObject whose virtual file paths are searched for parent UIDs
    :return: A set of parent UIDs
    '''
    parent_uids = set()
    for path_list in file_object.virtual_file_path.values():
        for virtual_path in path_list:
            with suppress(IndexError):
                parent_uids.add(split_virtual_path(virtual_path)[-2])  # second last element is the parent object
    return parent_uids


def get_uids_from_virtual_path(virtual_path: str) -> list[str]:
    '''
    Get all UIDs from a virtual file path (one element from the virtual path list for one root UID of a FW).

    :param virtual_path: A virtual path consisting of UIDs, separators ('|') and file paths
    :return: A list of UIDs
    '''
    parts = split_virtual_path(virtual_path)
    if len(parts) == 1:  # the virtual path of a FW consists only of its UID
        return parts
    return parts[:-1]  # included files have the file path as last element


def update_virtual_file_path(new_vfp: dict[str, list[str]], old_vfp: dict[str, list[str]]) -> dict[str, list[str]]:
    '''
    Get updated dict of virtual file paths.
    A file object can exist only once, multiple times inside the same firmware (e.g. sym links) or
    even in multiple different firmware images (e.g. common files across patch levels).
    Thus updating the virtual file paths dict requires some logic.
    This function returns the combined dict across newfound virtual paths and existing ones.

    :param new_vfp: current virtual file path dictionary
    :param old_vfp: old virtual file path dictionary (existing DB entry)
    :return: updated (merged) virtual file path dictionary
    '''
    for key in new_vfp:
        if key in old_vfp:
            old_vfp[key] = merge_vfp_lists(old_vfp[key], new_vfp[key])
        else:
            old_vfp[key] = new_vfp[key]
    return old_vfp
