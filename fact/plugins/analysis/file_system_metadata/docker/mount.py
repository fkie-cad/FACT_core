#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from subprocess import CalledProcessError, check_call

INPUT_DIR = Path('/work')
INPUT_FILE = INPUT_DIR / 'input.img'
MOUNT_DIR = Path('/root/mount_dir')
OUTPUT_FILE = INPUT_DIR / 'output.pickle'


@contextmanager
def mount(input_file: Path):
    try:
        check_call(f'mount -o ro,loop {input_file} {MOUNT_DIR}', shell=True)
        yield
    finally:
        check_call(f'umount {MOUNT_DIR}', shell=True)


def main():
    try:
        stats = INPUT_FILE.lstat()
        with mount(INPUT_FILE):
            result = _get_mounted_file_stats()
        _save_results(result, stats.st_uid, stats.st_gid)
    except FileNotFoundError:
        logging.error('Could not find the input file.')
    except CalledProcessError:
        logging.error('Error during mount.')


def _get_mounted_file_stats():
    result = []
    for file in MOUNT_DIR.rglob('*'):
        try:
            if not file.is_symlink() and file.is_file():
                result.append((file.name, str(file.relative_to(MOUNT_DIR)), _stat_to_dict(file.lstat())))
        except PermissionError:
            continue
    return result


def _stat_to_dict(stat_result: os.stat_result) -> dict[str, int | float]:
    return {
        'uid': stat_result.st_uid,
        'gid': stat_result.st_gid,
        'mode': stat_result.st_mode,
        'a_time': stat_result.st_atime,
        'c_time': stat_result.st_ctime,
        'm_time': stat_result.st_mtime,
    }


def _save_results(result, uid, gid):
    OUTPUT_FILE.write_text(json.dumps(result))
    os.chown(OUTPUT_FILE, uid, gid)


if __name__ == '__main__':
    main()
