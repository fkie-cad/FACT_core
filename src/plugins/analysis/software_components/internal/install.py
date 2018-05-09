import os
import sys

THIS_FILE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(THIS_FILE, '', 'internal'))
from scan_signatures import get_scanned_software


def scan():
    scanned_software = get_scanned_software('./signatures/os.yara')
    first = True

    with open('./code/__init__.py', 'w') as init_file:
        init_file.write('OS_LIST = [')
        for entry in scanned_software:
            if not first:
                init_file.write(', ')
            init_file.write('\'' + entry + '\'')
            first = False
        init_file.write(']\n')


if __name__ == '__main__':
    exit(scan())
