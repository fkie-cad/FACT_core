import binascii
import re
import string

NUMBER_OF_COLUMNS = 16
NUMBER_OF_ROWS = 8


def _process_ascii_bytes(bytes_in_ascii):
    allowed = string.ascii_letters + string.digits
    for index, char in enumerate(bytes_in_ascii):
        if char not in allowed:
            bytes_in_ascii = bytes_in_ascii[:index] + '.' + bytes_in_ascii[index + 1:]
    return bytes_in_ascii


def _process_hex_bytes(bytes_in_hex):
    result = ''
    odd = False
    for index, char in enumerate(bytes_in_hex):
        if odd:
            result += char + ' '
        else:
            result += char
        odd = not odd
    return _structure_hex_dump(result)


def _process_one_column(binary, i):
    offset = i * NUMBER_OF_COLUMNS
    part = binary[offset:offset + NUMBER_OF_COLUMNS]

    bytes_in_hex = binascii.b2a_hex(part).decode()
    bytes_in_hex = _process_hex_bytes(bytes_in_hex)

    bytes_in_ascii = part.decode(errors='replace')
    bytes_in_ascii = _process_ascii_bytes(bytes_in_ascii)

    return bytes_in_ascii, bytes_in_hex, offset


def create_hex_dump(binary):
    if len(binary) < NUMBER_OF_COLUMNS * NUMBER_OF_ROWS:
        return 1

    result = list()
    for i in range(NUMBER_OF_ROWS):
        bytes_in_ascii, bytes_in_hex, offset = _process_one_column(binary, i)
        result.append('0x{:<4x}  {}  |{}|'.format(offset, bytes_in_hex, bytes_in_ascii))

    return '\n'.join(result)


def _seperate_block(block_match):
    return block_match.group() + " "


def _structure_hex_dump(raw_hex):
    p = re.compile(r'([0-9a-fA-F]{2} ){4}')
    structured_hex = p.sub(_seperate_block, raw_hex)
    return structured_hex
