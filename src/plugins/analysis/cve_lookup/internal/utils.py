import re
from typing import List


def replace_characters_and_wildcards(attributes: List[str]) -> List[str]:
    for index, attribute in enumerate(attributes):
        if attribute == '*':
            attributes[index] = 'ANY'
        elif attribute == '-':
            attributes[index] = 'N/A'
        # if there are non-alphanumeric characters apart from underscore and escaped colon, escape them
        elif re.match(r'^.*[^a-zA-Z0-9_\\:].*$', attribute):
            attributes[index] = _escape_special_characters(attribute)
    return attributes


def _escape_special_characters(attribute: str) -> str:
    # a counter is incremented every time an escape character is added because it alters the string length
    index_shift = 0
    for characters in re.finditer(r'[^.]((?<!\\)[*?])[^.]|((?<!\\)[^a-zA-Z0-9\s?*_\\])', attribute):
        group = 2 if characters.span(1)[0] == -1 else 1
        start = characters.span(group)[0] + index_shift
        if start:
            attribute = f'{attribute[:start]}\\{attribute[start:]}'
            index_shift += 1

    return attribute
