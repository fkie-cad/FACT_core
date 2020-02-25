#!/usr/bin/env python3

import sys

from internal.extract_os_names import extract_names  # pylint: disable=import-error


def main():
    print(
        '-----------------------------------\n'
        'Installation of Software Components\n'
        '-----------------------------------'
    )
    extract_names()
    return 0


if __name__ == '__main__':
    sys.exit(main())
