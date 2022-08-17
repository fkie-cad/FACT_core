from re import finditer, match
from typing import Dict, List, NamedTuple, Tuple

CveEntry = NamedTuple(
    'CveEntry', [('cve_id', str), ('impact', Dict[str, str]), ('cpe_list', List[Tuple[str, str, str, str, str]])]
)
CveSummaryEntry = NamedTuple('CveSummaryEntry', [('cve_id', str), ('summary', str), ('impact', dict)])


def escape_special_characters(attribute: str) -> str:
    # a counter is incremented every time an escape character is added because it alters the string length
    index_shift = 0
    for characters in finditer(r'[^.]((?<!\\)[*?])[^.]|((?<!\\)[^a-zA-Z0-9\s?*_\\])', attribute):
        group = 2 if characters.span(1)[0] == -1 else 1
        start = characters.span(group)[0] + index_shift
        if start:
            attribute = f'{attribute[:start]}\\{attribute[start:]}'
            index_shift += 1

    return attribute


def replace_characters_and_wildcards(attributes: List[str]) -> List[str]:
    for index, attribute in enumerate(attributes):
        if attribute == '*':
            attributes[index] = 'ANY'
        elif attribute == '-':
            attributes[index] = 'N/A'
        # if there are non-alphanumeric characters apart from underscore and escaped colon, escape them
        elif match(r'^.*[^a-zA-Z0-9_\\:].*$', attribute):
            attributes[index] = escape_special_characters(attribute)
    return attributes


def get_field_string(fields: List[Tuple[str, str]]) -> str:
    return ', '.join([f'{name} {type_} NOT NULL' for name, type_ in fields])


def get_field_names(fields: List[Tuple[str, str]]) -> str:
    return ', '.join(list(zip(*fields))[0])


def unescape(string: str) -> str:
    return string.replace('\\', '')


class CveLookupException(Exception):
    def __init__(self, message: str):  # pylint: disable=super-init-not-called
        self.message = message

    def __str__(self):
        return self.message
