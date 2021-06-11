from typing import Dict, List


def split_virtual_path(virtual_path: str) -> List[str]:
    return [element for element in virtual_path.split('|') if element]


def join_virtual_path(*elements: str) -> str:
    return '|'.join(elements)


def get_base_of_virtual_path(virtual_path: str) -> str:
    return join_virtual_path(*split_virtual_path(virtual_path)[:-1])


def get_top_of_virtual_path(virtual_path: str) -> str:
    return split_virtual_path(virtual_path)[-1] if virtual_path else ''


def merge_vfp_lists(old_vfp_list: List[str], new_vfp_list: List[str]) -> List[str]:
    '''
    virtual file paths (VFPs) with the same base are updated and should be replaced
    VFPs with different bases correspond to different archives in the firmware and should be kept
    '''
    old_vfp_by_base = _split_vfp_list_by_base(old_vfp_list)
    new_vfp_by_base = _split_vfp_list_by_base(new_vfp_list)
    for base in new_vfp_by_base:
        old_vfp_by_base[base] = new_vfp_by_base[base]
    return [vfp for vfp_list in old_vfp_by_base.values() for vfp in vfp_list]


def _split_vfp_list_by_base(vfp_list: List[str]) -> Dict[str, List[str]]:
    '''
    for virtual file path (VFP) list ['uid|/dir/file', 'uid|/file2', 'uid|other_uid|/file3']
    the result would be {'uid': ['uid|/dir/file', 'uid|/file2'], 'uid|other_uid': ['uid|other_uid|/file3']}
    '''
    vfp_list_by_base = {}
    for path in vfp_list:
        vfp_list_by_base.setdefault(get_base_of_virtual_path(path), []).append(path)
    return vfp_list_by_base
