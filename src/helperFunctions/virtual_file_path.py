from __future__ import annotations

from typing import Dict, List, TypeAlias

VFP: TypeAlias = str
VfpDict: TypeAlias = Dict[str, List[VFP]]


def get_paths_for_all_parents(vfp_dict: VfpDict) -> list[VFP]:
    """
    Get a combined list of all paths in all parents (without duplicates)
    :param vfp_dict: A vfp dict (typically found in FileObject.virtual_file_path)
    """
    if not vfp_dict:
        return []
    return list(set.union(*(set(vfp_list) for vfp_list in vfp_dict.values())))


def get_some_vfp(vfp_dict: VfpDict) -> VFP | None:
    """Just get some random virtual file path."""
    for vfp_list in vfp_dict.values():
        return vfp_list[0]
    return None


def filter_vpf_dict(vfp_dict: dict[str, list[str]], parent_uids: set[str]) -> dict[str, list[str]]:
    """
    Get only VFPs from parent files that are contained in `parent_uids`.
    :param vfp_dict: A virtual file path dict
    :param parent_uids: A set of allowed parent UIDs (VFPs from other parent files are filtered out)
    """
    return {k: v for k, v in vfp_dict.items() if k in parent_uids}
