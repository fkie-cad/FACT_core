import yara


def yara_match_to_dict(match: yara.Match) -> dict:
    """Converts a ``yara.Match`` to the format that :py:class:`analysis.YaraPluginBase` would return."""
    # see YARA docs: https://yara.readthedocs.io/en/latest/yarapython.html#yara.StringMatchInstance
    strings = [
        (string_instance.offset, string_match.identifier, string_instance.matched_data.decode(errors='replace'))
        for string_match in match.strings  # type: yara.StringMatch
        for string_instance in string_match.instances  # type: yara.StringMatchInstance
    ]

    return {
        'meta': {
            key: match.meta.get(key)
            for key in ('open_source', 'software_name', 'website', 'date', 'author', 'description')
        },
        'rule': match.rule,
        'strings': strings,
    }
