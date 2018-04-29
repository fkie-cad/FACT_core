import os
import sys

THIS_FILE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(THIS_FILE, '', 'internal'))
from scan_signatures import get_scanned_software

scanned_software = get_scanned_software("./signatures/os.yara")
first = True

init_file = open("./code/__init__.py","w")
init_file.write("OS_LIST = [")
for entry in scanned_software:
    if first == False:
        init_file.write(",")
    init_file.write("'" + entry + "'")
    first = False
init_file.write("]")
init_file.close()