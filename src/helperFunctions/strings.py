import string
import re


def find_all_strings(input_data, min_length=4):
    byte_strings = find_all_printable_patterns(input_data, min_length)
    strings = decode_strings(byte_strings)

    utf16_strings = find_all_utf16_patterns(input_data, min_length)
    strings.extend(decode_strings(utf16_strings, "utf-16"))

    strings = remove_duplicates(strings)
    strings.sort()
    return strings


def find_all_printable_patterns(input_bytes, min_length):
    pattern_templ = '[{}]{{{},}}'

    # '+ "\x5c\x5c"' fixes the backslash problem
    printable_pattern = pattern_templ.format(string.printable + "\x5c\x5c", min_length)

    string_re = re.compile(printable_pattern.encode('utf-8'))
    return string_re.findall(input_bytes)


def find_all_utf16_patterns(input_bytes, min_length):
    regex = "(?:[{}]\x00){{{},}}".format(string.printable + "\x5c\x5c", min_length).encode()
    # regex will match typical UTF-16 sequences like "a\x00b\x00c\x00"
    matches = re.findall(regex, input_bytes)
    return matches


def decode_strings(byte_strings, encoding="utf-8"):
    return [s.decode(encoding) for s in byte_strings]


def remove_duplicates(list_object):
    return list(set(list_object))
