#!/usr/bin/env python3
import subprocess
import sys
from base64 import b64encode
from json import dumps
from typing import Tuple

FIRMWARE_ROOT = '/opt/firmware_root/'
ARCH = sys.argv[1]
FILE_PATH = FIRMWARE_ROOT + sys.argv[2]
TIMEOUT_ERROR_EXIT_CODES = [124, 128 + 9]


def get_output_error_and_return_code(command: str) -> Tuple[bytes, bytes, int]:
    process = subprocess.run(command, capture_output=True, shell=True)
    return process.stdout, process.stderr, process.returncode


def get_output(command: str) -> dict:
    std_out, std_err, return_code = get_output_error_and_return_code(command)
    if return_code in TIMEOUT_ERROR_EXIT_CODES:
        return {'error': 'timeout'}
    return {
        'stdout': encode_as_str(std_out),
        'stderr': encode_as_str(std_err),
        'return_code': return_code
    }


def encode_as_str(std_out):
    return b64encode(std_out).decode()


def main():
    result = {}
    for parameter in ['-h', '--help', '-help', '--version', ' ']:
        command = f'timeout -s SIGKILL 1 qemu-{ARCH} {FILE_PATH} {parameter}'
        result[parameter] = get_output(command)

    command = f'timeout -s SIGKILL 2 qemu-{ARCH} -strace {FILE_PATH}'
    result['strace'] = get_output(command)
    print(dumps(result), flush=True)


if __name__ == '__main__':
    main()
    sys.exit(0)
