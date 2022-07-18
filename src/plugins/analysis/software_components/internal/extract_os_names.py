import json
import os
from contextlib import suppress

from common_helper_files import get_string_list_from_file, write_binary_to_file

SIGNATURE_PATH = '../signatures/os.yara'
TARGET_PATH = '../bin/__init__.py'


def get_software_names(yara_file_path):
    scanned_software = []

    for line in get_string_list_from_file(yara_file_path):
        line = line.strip()
        parts_of_line = line.split('=')
        if parts_of_line[0].strip() == 'software_name':
            software_name = parts_of_line[1].strip()
            software_name = software_name.replace('"', '')
            scanned_software.append(software_name)

    return scanned_software


def extract_names(yara_file_path=SIGNATURE_PATH, target_path=TARGET_PATH):
    stashed_directory = os.getcwd()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    software_names = get_software_names(yara_file_path)

    with suppress(FileExistsError):
        os.mkdir(os.path.dirname(target_path))

    binary_string = f'OS_LIST = {json.dumps(software_names)}\n'
    write_binary_to_file(file_binary=binary_string.encode(), file_path=target_path, overwrite=True)

    os.chdir(stashed_directory)
