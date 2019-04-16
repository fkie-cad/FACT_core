#!/usr/bin/env python3
import subprocess
import sys
from pickle import dumps
from typing import Tuple

FIRMWARE_ROOT = '/opt/firmware_root/'
ARCH = sys.argv[1]
FILE_PATH = FIRMWARE_ROOT + sys.argv[2]
TIMEOUT_ERROR_EXIT_CODES = [124, 128 + 9]


def get_output_error_and_return_code(command: str) -> Tuple[bytes, bytes, int]:
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    return process.stdout, process.stderr, process.returncode


def get_output(command: str) -> dict:
    std_out, std_err, return_code = get_output_error_and_return_code(command)
    if return_code in TIMEOUT_ERROR_EXIT_CODES:
        return {'error': 'timeout'}
    return {'stdout': std_out, 'stderr': std_err, 'return_code': return_code}


def main():
    result = {}
    for parameter in ['-h', '--help', '-help', '--version', ' ']:
        command = f'timeout --signal=SIGKILL 1s qemu-{ARCH} {FILE_PATH} {parameter}'
        result[parameter] = get_output(command)

    command = f'timeout --signal=SIGKILL 2s qemu-{ARCH} -strace {FILE_PATH}'
    result['strace'] = get_output(command)
    sys.stdout.buffer.write(dumps(result))


if __name__ == '__main__':
    main()
    sys.exit(0)
