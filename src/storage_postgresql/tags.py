from typing import Dict

from objects.file import FileObject


def collect_analysis_tags(file_object: FileObject) -> dict:
    tags = {}
    for plugin, analysis in file_object.processed_analysis.items():
        if 'tags' not in analysis:
            continue
        for tag_type, tag in analysis['tags'].items():
            if tag_type != 'root_uid' and tag['propagate']:
                append_unique_tag(tags, tag, plugin, tag_type)
    return tags


def append_unique_tag(unique_tags: Dict[str, dict], tag: dict, plugin_name: str, tag_type: str) -> None:
    if plugin_name in unique_tags:
        if tag_type in unique_tags[plugin_name] and tag not in unique_tags[plugin_name].values():
            unique_tags[plugin_name][f'{tag_type}-{len(unique_tags[plugin_name])}'] = tag
        else:
            unique_tags[plugin_name][tag_type] = tag
    else:
        unique_tags[plugin_name] = {tag_type: tag}
