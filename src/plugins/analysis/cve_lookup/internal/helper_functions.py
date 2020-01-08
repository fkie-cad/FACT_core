from re import finditer, match
from typing import List


def escape_special_characters(attribute: str) -> str:
    # a counter is incremented every time an escape character is added because it alters the string length
    counter = 0
    for characters in finditer(r'[^.]((?<!\\)[*?])[^.]|((?<!\\)[^a-zA-Z0-9\s?*_\\])', attribute):
        group = 2 if characters.span(1)[0] == -1 else 1
        start = characters.span(group)[0] + counter
        if start:
            attribute = attribute[:start] + '\\' + attribute[start:]
            counter += 1

    return attribute


def unbind(attributes: List[str]) -> List[str]:
    for index, attribute in enumerate(attributes):
        if attribute == '*':
            attributes[index] = 'ANY'
        elif attribute == '-':
            attributes[index] = 'NA'
        # if there are no non-alphanumeric characters apart from underscore and escaped colon, continue
        elif not match(r'^.*[^a-zA-Z0-9_\\:].*$', attribute):
            continue
        else:
            attributes[index] = escape_special_characters(attribute)

    return attributes
