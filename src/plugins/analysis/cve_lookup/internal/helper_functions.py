from typing import NamedTuple


class CveEntry(NamedTuple):
    '''
    A named tuple that represents a CVE entry.
    '''

    cve_id: str
    summary: str
    impact: dict[str, str]
    cpe_entries: list[tuple[str, str, str, str, str]]


def replace_characters_and_wildcards(attributes: list[str]) -> list[str]:
    '''
    Replaces wildcard characters ('*' and '-') with their respective placeholders in the given attributes.
    '''
    for index, attribute in enumerate(attributes):
        if attribute == '*':
            attributes[index] = 'ANY'
        elif attribute == '-':
            attributes[index] = 'N/A'
    return attributes
