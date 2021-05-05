from typing import Dict


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
