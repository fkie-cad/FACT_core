from typing import Dict

from objects.file import FileObject


class TagColor:
    '''
    A class containing the different colors the tags may have. `TagColor.ALL` contains a list of all colors.
    '''
    GRAY = 'secondary'
    BLUE = 'primary'
    GREEN = 'success'
    LIGHT_BLUE = 'info'
    ORANGE = 'warning'
    RED = 'danger'
    LIGHT = 'light'
    DARK = 'dark'
    ALL = [GRAY, BLUE, GREEN, LIGHT_BLUE, ORANGE, RED, LIGHT, DARK]


def check_tags(file_object: FileObject, analysis_name: str) -> Dict:
    '''
    Checks if a file object has tags associated with a specific analysis plugin.
    Returns a dictionary with `notags` set to `False` and containing the tags, plugin and uid if yes, or a dictionary
    with `notags` set to `True` otherwise.

    :param file_object: The file object.
    :param analysis_name: The analysis plugin.
    :return: A dictionary with the tag data.
    '''

    tags, root_uid = None, None
    if analysis_name in file_object.processed_analysis and 'tags' in file_object.processed_analysis[analysis_name]:
        try:
            root_uid = file_object.processed_analysis[analysis_name]['tags'].pop('root_uid')
        except (KeyError, AttributeError):
            return dict(notags=True)
        tags = file_object.processed_analysis[analysis_name]['tags']
    return dict(notags=False, tags=tags, plugin=analysis_name, uid=root_uid) if root_uid else dict(notags=True)


def add_tags_to_object(file_object: FileObject, analysis_name: str) -> FileObject:
    '''
    Adds the tags from an analysis plugin to the analysis tags of a file object.

    :param file_object: The file object.
    :param analysis_name: The analysis plugin.
    :return: The updated file object.
    '''
    if analysis_name in file_object.processed_analysis and 'tags' in file_object.processed_analysis[analysis_name]:
        tags = file_object.processed_analysis[analysis_name]['tags']
        file_object.analysis_tags[analysis_name] = tags
    return file_object


def update_tags(old_tags: dict, plugin_name: str, tag_name: str, tag: dict) -> dict:
    '''
    Updates the plugin `plugin_name` of a tag dictionary `old_tags` with a new entry with key `tag_name` and
    value `tag`.

    :param old_tags: The tag dictionary that is updated.
    :param plugin_name: The analysis plugin.
    :param tag_name: The tag label.
    :param tag: The new tag entry.
    '''
    _check_tag_integrity(tag)
    old_tags.setdefault(plugin_name, {})[tag_name] = tag
    return old_tags


def _check_tag_integrity(tag: Dict) -> (bool, str):
    if any(key not in tag for key in ['value', 'color', 'propagate']):
        raise ValueError('missing key')
    if tag['color'] not in TagColor.ALL:
        raise ValueError('bad tag color')
    if not isinstance(tag['value'], str):
        raise ValueError('tag value has to be a string')
    if tag['propagate'] not in [True, False]:
        raise ValueError('tag propagate key has to be a boolean')
