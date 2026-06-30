from __future__ import annotations

import json
from pathlib import Path

import yara

SIGNATURE_PATH = Path(__file__).parent.parent / 'signatures/os.yara'
TARGET_PATH = Path(__file__).parent.parent / 'bin/__init__.py'


def get_software_names(yara_file_path: Path) -> list[str]:
    rules = yara.compile(str(yara_file_path))
    software_names = []
    for rule in rules:
        if not rule.meta:
            continue
        if software_name := rule.meta.get('software_name'):
            software_names.append(software_name)
    return software_names


def extract_names(yara_file_path: Path = SIGNATURE_PATH, target_path: Path = TARGET_PATH) -> None:
    software_names = get_software_names(yara_file_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    os_list = f'OS_LIST = {json.dumps(software_names)}\n'
    target_path.write_text(os_list)
