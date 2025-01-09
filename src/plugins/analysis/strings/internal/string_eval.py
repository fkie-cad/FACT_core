"""
Credits:
Original version by Paul Schiffer created during Firmware Bootcamp WT16/17 at University of Bonn
Refactored and improved by Fraunhofer FKIE
"""

from __future__ import annotations

import re

REGEX_LOWER = re.compile(r'[a-z]')
REGEX_CAPITAL = re.compile(r'[A-Z]')
REGEX_WORD = re.compile(r'[a-zA-Z]')
REGEX_NO_WORD = re.compile(r'\W')
QUAD_CHAR_REGEX = re.compile(r'(\S)\1\1\1')
YEAR_REGEX = re.compile(r'(19\d\d)|(20\d\d)')
PATH_REGEX = re.compile(r'(/[\w-]+)+(.[a-zA-Z]+)')
VERSION_REGEX = re.compile(r'\d+\.(\d+\.?)+')
FORMAT_STR_REGEX = re.compile(r'%s|%lu|%u|%lf|%f|%i|%d')
MAIL_REGEX = re.compile(
    r'(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))'
    r'@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))'
)
PREFIX_REGEX = re.compile(r'(^_+)|^\.')
PARAMETER_REGEX = re.compile(r'^\s*-{1,2}')
HTML_REGEX = re.compile(r'</?[^\\()$\[\]§.,?<>;|!]+>')

DICTIONARY = {'version', 'v.', 'http', 'ftp', 'usage', 'Usage', 'ssh', 'SSH', 'password', 'Version'}


def calculate_relevance_score(string: str) -> float:
    """
    Uses several heuristics to compute a score which should reflect the relevance of a given string. The score can be
    negative and there are no upper or lower bounds.
    """
    return (
        _get_length_score(string)
        + _get_rare_special_character_score(string)
        + _get_special_character_ratio_score(string)
        + _get_case_ratio_score(string)
        + _get_quad_characters_score(string)
        + _get_dictionary_score(string)
        + _get_path_score(string)
        + _get_possible_year_score(string)
        + _get_possible_version_number_score(string)
        + _get_format_string_score(string)
        + _get_mail_address_score(string)
        + _get_underscore_or_period_at_beginning_score(string)
        + _get_parameter_score(string)
        + _get_html_score(string)
    )


def _get_length_score(string: str) -> float:
    return len(string) / 2


def _get_rare_special_character_score(string: str) -> float:
    rare_characters = ['^', '°', '§', '´', '`', '{', '}']
    return -15 * sum(1 for character in rare_characters if character in string)


def _get_special_character_ratio_score(string: str) -> float:
    match_num_non_word = len(REGEX_NO_WORD.findall(string))
    match_num_word = len(REGEX_WORD.findall(string))
    return _ratio_word_non_word_helper(match_num_word, match_num_non_word)


def _ratio_word_non_word_helper(num_word: int, num_non_word: int) -> int:
    ratio = num_word if num_non_word == 0 else num_word / num_non_word
    return 15 if ratio >= 2 else -15  # noqa: PLR2004


def _get_case_ratio_score(string: str) -> float:
    match_num_lower = len(REGEX_LOWER.findall(string))
    match_num_capital = len(REGEX_CAPITAL.findall(string))
    return _case_ratio_helper(match_num_lower, match_num_capital)


def _case_ratio_helper(num_lower: int, num_capital: int) -> float:
    # all caps
    if num_lower == 0 and num_capital >= 6:  # noqa: PLR2004
        return num_capital / 2
    case_ratio = num_lower if num_capital == 0 else num_lower / num_capital
    return 10 if case_ratio > 1 else -10


def _get_quad_characters_score(string: str) -> int:
    matches = QUAD_CHAR_REGEX.findall(string)
    return -25 * len(matches)


def _get_dictionary_score(string: str) -> int:
    return 30 * sum(1 for word in DICTIONARY if word in string)


def _get_possible_year_score(string: str) -> int:
    matches = YEAR_REGEX.search(string)
    return 20 if matches else 0


def _get_path_score(string: str) -> int:
    matches = PATH_REGEX.search(string)
    return 100 if matches else 0


def _get_possible_version_number_score(string: str) -> int:
    matches = VERSION_REGEX.search(string)
    return 35 if matches else 0


def _get_format_string_score(string: str) -> int:
    matches = FORMAT_STR_REGEX.finditer(string)
    return -15 * len(list(matches))


def _get_mail_address_score(string: str) -> int:
    match = MAIL_REGEX.search(string)
    return 150 if match else 0


def _get_underscore_or_period_at_beginning_score(string: str) -> int:
    match = PREFIX_REGEX.search(string)
    return -25 if match else 0


def _get_parameter_score(string: str) -> int:
    match = PARAMETER_REGEX.search(string)
    return 35 if match and len(string) > 6 else 0  # noqa: PLR2004


def _get_html_score(string: str) -> int:
    match = HTML_REGEX.search(string)
    return 15 if match else 0
