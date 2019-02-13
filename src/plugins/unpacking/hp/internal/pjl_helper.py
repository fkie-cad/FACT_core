import re
from pathlib import Path

from common_helper_files import get_safe_name, write_binary_to_file

NAME_FIELD_MAX = 102


def get_pjl_commands(input_data):
    pjl_instructions = []
    tmp = list(re.finditer(rb'@PJL [ =.!,?\w]+', input_data))
    for item in tmp:
        pjl_instructions.append(_match_to_pjl_dict(item))
    return pjl_instructions


def extract_all_upgrades(binary_data, pjl_commands, extraction_dir):
    for item in pjl_commands:
        if _is_upgrade(item):
            _extract_file_from_upgrade(binary_data, item, extraction_dir)


def extract_fingerprint(input_data, tmp_dir):
    fingerprint = _get_file_fingerprint(input_data)
    if fingerprint:
        store_path = Path(tmp_dir, 'fingerprint.txt')
        write_binary_to_file(fingerprint, str(store_path), overwrite=False, file_copy=True)


def _get_end_postion_of_first_preamble(raw_binary):
    tmp = re.search(rb'\x25\x2d12345X\x0a?', raw_binary)
    if tmp:
        return tmp.end()
    return 0


def _get_name_of_upgrade(raw_binary, upgrade_command):
    tmp = re.search(rb'\xa8\x01([\w ]+)  [\w ]+', raw_binary[upgrade_command['end_offset']:upgrade_command['end_offset'] + NAME_FIELD_MAX])
    if tmp is not None:
        tmp = tmp.group(1).decode('utf-8', 'ignore')
        tmp = _remove_uneccessary_spaces(tmp)
    return tmp


def _get_size_of_upgrade(upgrade_command):
    tmp = re.match(rb'SIZE=([0-9]+)', upgrade_command['value'])
    tmp = int(tmp.group(1))
    return tmp


def _get_type_and_value(raw_command):
    tmp = re.search(rb'@PJL ([=\w]+) ?([ =.!,?\w]+)?', raw_command)
    tmp_type = tmp.group(1)
    tmp_value = tmp.group(2)
    return tmp_type, tmp_value


def _is_upgrade(pjl_command):
    return pjl_command['type'] == b'UPGRADE'


def _remove_uneccessary_spaces(input_string):
    tmp = input_string.split()
    tmp = ' '.join(tmp)
    return tmp


def _get_file_fingerprint(input_data):
    prefix = re.search(rb'\-\-\=\<\/Begin HP Signed File Fingerprint\\\>\=\-\-', input_data)
    if prefix:
        suffix = re.search(rb'\-\-\=\<\/End HP Signed File Fingerprint\\\>\=\-\-', input_data)
        if suffix:
            return input_data[prefix.start():suffix.end()]
    return None


def _match_to_pjl_dict(command_match):
    pjl_dict = {'raw': command_match.group(0)}
    pjl_dict['begin_offset'], pjl_dict['end_offset'] = command_match.span()
    pjl_dict['type'], pjl_dict['value'] = _get_type_and_value(pjl_dict['raw'])
    return pjl_dict


def _extract_file_from_upgrade(binary_data, upgrade_command, extraction_dir):
    file_name = _get_name_of_upgrade(binary_data, upgrade_command)
    file_binary = _get_binary_of_upgrade(binary_data, upgrade_command, file_name)
    if file_name:
        file_name = '{}.bin'.format(get_safe_name(file_name, max_size=80))
    else:
        file_name = '{}.bin'.format(upgrade_command['begin_offset'])
    file_path = Path(extraction_dir, file_name)
    write_binary_to_file(file_binary, str(file_path), overwrite=False, file_copy=True)


def _get_binary_of_upgrade(binary_data, upgrade_command, file_name):
    if file_name:
        data_begin_offset = upgrade_command['end_offset'] + NAME_FIELD_MAX
        data_end_offset = upgrade_command['end_offset'] + _get_size_of_upgrade(upgrade_command) + 2
    else:
        data_begin_offset = _get_end_postion_of_first_preamble(binary_data[upgrade_command['end_offset']:upgrade_command['end_offset'] + NAME_FIELD_MAX]) + upgrade_command['end_offset']
        data_end_offset = data_begin_offset + _get_size_of_upgrade(upgrade_command)
    return binary_data[data_begin_offset:data_end_offset]
