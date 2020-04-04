class TagColor:
    GRAY = 'secondary'
    BLUE = 'primary'
    GREEN = 'success'
    LIGHT_BLUE = 'info'
    ORANGE = 'warning'
    RED = 'danger'
    LIGHT = 'light'
    DARK = 'dark'
    ALL = [GRAY, BLUE, GREEN, LIGHT_BLUE, ORANGE, RED, LIGHT, DARK]


def check_tags(file_object, analysis_name):
    tags, root_uid = None, None
    if analysis_name in file_object.processed_analysis and 'tags' in file_object.processed_analysis[analysis_name]:
        try:
            root_uid = file_object.processed_analysis[analysis_name]['tags'].pop('root_uid')
        except (KeyError, AttributeError):
            return dict(notags=True)
        tags = file_object.processed_analysis[analysis_name]['tags']
    return dict(notags=False, tags=tags, plugin=analysis_name, uid=root_uid) if root_uid else dict(notags=True)


def add_tags_to_object(file_object, analysis_name):
    if analysis_name in file_object.processed_analysis and 'tags' in file_object.processed_analysis[analysis_name]:
        tags = file_object.processed_analysis[analysis_name]['tags']
        file_object.analysis_tags[analysis_name] = tags
    return file_object


def update_tags(old_tags, plugin_name, tag_name, tag):
    tag_is_stable, message = check_tag_integrity(tag)

    if not tag_is_stable:
        raise ValueError(message)

    if plugin_name not in old_tags:
        old_tags[plugin_name] = {tag_name: tag}

    old_tags[plugin_name][tag_name] = tag

    return old_tags


def check_tag_integrity(tag):
    if any(key not in tag for key in ['value', 'color', 'propagate']):
        return False, 'missing key'

    if tag['color'] not in TagColor.ALL:
        return False, 'bad tag color'

    if not isinstance(tag['value'], str):
        return False, 'tag value has to be a string'

    if tag['propagate'] not in [True, False]:
        return False, 'tag propagate key has to be a boolean'

    return True, 'empty'
