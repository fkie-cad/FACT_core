from helperFunctions.virtual_file_path import merge_vfp_lists
from objects.file import FileObject


def update_included_files(new_object: FileObject, old_object: dict) -> list:
    '''
    Get updated list of included files of an object.
    This is done by joining newfound included files with already found included files.

    :param new_object: Current file object with newly discovered included files
    :param old_object: Current database state of same object with existing included files
    :return: a list containing all included files
    '''
    old_fi = old_object['files_included']
    old_fi.extend(new_object.files_included)
    old_fi = list(set(old_fi))
    return old_fi


def update_virtual_file_path(new_object: FileObject, old_object: dict) -> dict:
    '''
    Get updated dict of virtual file paths.
    A file object can exist only once, multiple times inside the same firmware (e.g. sym links) or
    even in multiple different firmware images (e.g. common files across patch levels).
    Thus updating the virtual file paths dict requires some logic.
    This function returns the combined dict across newfound virtual paths and existing ones.

    :param new_object: Current file object with newly discovered virtual paths
    :param old_object: Current database state of same object with existing virtual paths
    :return: a dict containing all virtual paths
    '''
    old_vfp = old_object['virtual_file_path']
    for key in new_object.virtual_file_path.keys():
        if key in old_vfp:
            old_vfp[key] = merge_vfp_lists(old_vfp[key], new_object.virtual_file_path[key])
        else:
            old_vfp[key] = new_object.virtual_file_path[key]
    return old_vfp
