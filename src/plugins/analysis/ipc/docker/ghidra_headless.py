#!/usr/bin/env python3
import argparse
import os
import sys
import tempfile
from pathlib import Path


def parse_arguments() -> argparse.Namespace():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--ghidra_path', nargs='?', default='/opt/ghidra', help='path to Ghidra')
    parser.add_argument('file_path', help='path to binary/firmware')
    parser.add_argument('result_path', nargs='?', default='', help='result path')
    args = parser.parse_args()
    return args


def check_ghidra(ghidra_path: Path) -> bool:
    """
    Checks if Ghidra executable exists
    """
    if not ghidra_path.exists():
        print(f'{ghidra_path} does not exist!')
        print('Try change the ghidra_path with the -g option.')
        sys.exit(-1)


def get_ghidra_command(ghidra_path: Path, project_path: Path, file_path: Path, result_path: Path) -> str:
    """
    Builds the Ghidra command
    """
    headless_path = ghidra_path / 'support/analyzeHeadless'
    pre_script = 'headless_prescript.py'
    post_script = 'ipc_analyzer.py'
    project_name = 'tmp_ghidra_project'
    return f'{headless_path} {project_path} {project_name} -readOnly \
            -import {file_path} -preScript {pre_script} -postScript {post_script} {result_path}'


def get_binaries(file_path: Path) -> list[Path]:
    """
    Get all executable files
    """
    if file_path.is_file():
        return [file_path]
    binaries = []
    for file in file_path.iterdir():
        if file.is_symlink():
            continue
        if file.is_dir():
            binaries += get_binaries(file)
        elif os.access(file, os.X_OK):
            binaries.append(file)
    return binaries


def run_ghidra(ghidra_path: Path, file_path: Path, result_path: Path) -> None:
    """
    Builds Ghidra command and runs exporter script
    """
    check_ghidra(ghidra_path)
    with tempfile.TemporaryDirectory() as tmp_dir:
        project_path = Path('/tmp') / tmp_dir
        binaries = sorted(get_binaries(file_path))
        for binary in binaries:
            cmd = get_ghidra_command(ghidra_path, project_path, binary, result_path)
            os.system(cmd)


def main() -> int:
    args = parse_arguments()
    ghidra_path = Path(args.ghidra_path)
    file_path = Path(args.file_path)
    result_path = Path(args.result_path)
    run_ghidra(ghidra_path, file_path, result_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
