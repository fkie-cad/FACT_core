#!/usr/bin/env python3

import os
import sys
from contextlib import suppress


def get_scanned_software(yara_signature_file):
    with open(yara_signature_file, 'r') as file:
        scanned_software = []
        line = file.readline()
        while line:
            line = line.strip()
            parts_of_line = line.split('=')
            if parts_of_line[0].strip() == 'software_name':
                software_name = parts_of_line[1].strip()
                software_name = software_name.replace('"', '')
                scanned_software.append(software_name)
            line = file.readline()
    return scanned_software


def scan():
    stashed_directory = os.getcwd()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    scanned_software = get_scanned_software('./signatures/os.yara')
    first = True

    with suppress(FileExistsError):
        os.mkdir('./bin')

    with open('./bin/__init__.py', 'w') as init_file:
        init_file.write('OS_LIST = [')
        for entry in scanned_software:
            if not first:
                init_file.write(', ')
            init_file.write('\'' + entry + '\'')
            first = False
        init_file.write(']\n')

    os.chdir(stashed_directory)


def main():
    print(
        '-----------------------------------\n'
        'Installation of Software Components\n'
        '-----------------------------------'
    )
    scan()
    return 0


if __name__ == '__main__':
    exit(main())
