from __future__ import annotations


def split_virtual_path(virtual_path: str) -> list[str]:
    return [element for element in virtual_path.split('|') if element]


def join_virtual_path(*elements: str) -> str:
    return '|'.join(elements)


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
            old_vfp[key] = list(set(old_vfp[key]).union(new_vfp[key]))
        else:
            old_vfp[key] = new_vfp[key]
    return old_vfp
