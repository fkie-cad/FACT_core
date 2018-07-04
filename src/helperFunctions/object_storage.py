from objects.file import FileObject


def update_analysis_tags(new_object: FileObject, old_object: dict) -> dict:
    old_tags = old_object['analysis_tags'] if 'analysis_tags' in old_object else {}
    new_tags = new_object.analysis_tags
    for key in new_tags.keys():
        old_tags[key] = new_tags[key]
    return old_tags


def update_included_files(new_object: FileObject, old_object: dict) -> list:
    old_fi = old_object['files_included']
    new_fi = new_object.files_included
    old_fi.extend(new_fi)
    old_fi = list(set(old_fi))
    return old_fi


def update_virtual_file_path(new_object: FileObject, old_object: dict) -> dict:
    old_vfp = old_object['virtual_file_path']
    new_vfp = new_object.virtual_file_path
    for key in new_vfp.keys():
        old_vfp[key] = new_vfp[key]
    return old_vfp
