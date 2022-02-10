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
