#!/usr/bin/env python3

import os
import sys

THIS_FILE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(THIS_FILE, '.', 'internal'))
from internal.extract_os_names import extract_names


def main():
    print(
        '-----------------------------------\n'
        'Installation of Software Components\n'
        '-----------------------------------'
    )
    extract_names()
    return 0


if __name__ == '__main__':
    exit(main())
