import string
from typing import AnyStr, List


def _str_to_hex_element_list(input_str: AnyStr) -> List[str]:
    return [hex(ord(c) if isinstance(c, str) else c)[2:].upper() for c in input_str]


LETTERS = _str_to_hex_element_list(string.ascii_letters)
NUMBERS = _str_to_hex_element_list(string.digits)
UPPER_HEX = _str_to_hex_element_list(bytes(range(128, 255)))
NULL = ['00', 'FF']


REPLACEMENT_CLASSES = [
    (LETTERS, 'number'),
    (NUMBERS, 'built_in'),
    (UPPER_HEX, 'keyword'),
    (NULL, 'comment'),
]


def highlight_hex(hex_str: str) -> str:
    for char_class, style_class in REPLACEMENT_CLASSES:
        for char in char_class:
            while f' {char} ' in hex_str:
                hex_str = hex_str.replace(f' {char} ', f' <span class="hljs-{style_class}">{char}</span> ')
    return hex_str
