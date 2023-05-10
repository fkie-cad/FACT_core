from __future__ import annotations


def get_paths_for_all_parents(vfp_dict: dict[str, list[str]]) -> list[str]:
    """
    Get a combined list of all paths in all parents (without duplicates)
    :param vfp_dict: A vfp dict (typically found in FileObject.virtual_file_path)
    """
    if not vfp_dict:
        return []
    return list(set.union(*(set(vfp_list) for vfp_list in vfp_dict.values())))
