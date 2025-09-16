from __future__ import annotations

import logging
import re
import string
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .database.schema import Cve

BASE_DIR = Path(__file__).parent
GROUP_1_PATH = BASE_DIR / 'group_1.txt'
GROUP_2_PATH = BASE_DIR / 'group_2.txt'

with GROUP_1_PATH.open('r') as f1, GROUP_2_PATH.open('r') as f2:
    GROUP_1 = f1.read().splitlines()
    GROUP_2 = f2.read().splitlines()

PATTERNS_1 = [re.compile(rf'(?:"){re.escape(word)}(?:-|")') for word in GROUP_1]
PATTERNS_2 = [re.compile(rf'(?:\b|_){re.escape(word)}(?:\b|-)') for word in GROUP_2]
# it is unclear which tools are included but two of these should usually be at the start of the tool string section
TOOLS_START_OFFSET_REGEX = re.compile(
    rb'((\[|\[\[|acping|addgroup|adduser|adjtimex|ar|arp|arping|ash|awk|basename|busybox|cat|df)\x00{1,7}){2}'
)
# the strings may be aligned to 4 or 8 bytes => up to 7 null bytes padding
TOOL_NAME_REGEX = re.compile(rb'(([a-zA-Z0-9\[_.-])+\x00{1,7})+')
TOOL_NAME_CHARS = string.ascii_lowercase + '['
MIN_TOOL_COUNT = 5


def filter_busybox_cves(file_path: str, cves: dict[str, Cve]) -> dict[str, Cve]:
    """
    Filters the BusyBox CVEs based on the components present in the binary file and the specified version.
    """
    components = get_busybox_components(file_path)
    if not components:
        return cves
    return filter_cves_by_component(file_path, cves, components)


def get_busybox_components(file_path: str) -> list[str]:
    """
    Extracts the BusyBox components from the binary file.
    """
    file_content = Path(file_path).read_bytes()
    while True:
        start_match = TOOLS_START_OFFSET_REGEX.search(file_content)
        if not start_match:
            return []
        start_offset = start_match.start()
        tools_match = TOOL_NAME_REGEX.match(file_content[start_offset:])
        if tools_match and (tools := _find_tools(tools_match.group())):
            return tools
        file_content = file_content[start_offset + 2 :]


def _find_tools(tool_str_block: bytes) -> list[str]:
    tools = {
        tool_name
        for entry in tool_str_block.split(b'\x00')
        if (tool_name := entry.decode()) and any(tool_name.startswith(char) for char in TOOL_NAME_CHARS)
    }
    if len(tools) < MIN_TOOL_COUNT:  # could be a false positive; there should usually be at least 10 tools
        return []
    return sorted(tools)


def filter_cves_by_component(file_path: str, cves: dict[str, Cve], components: list[str]) -> dict[str, Cve]:
    """
    Filters CVEs based on the components present in the BusyBox binary file.
    """
    filtered_cves = {}
    for cve_id, cve in cves.items():
        matched_words = get_matched_words(cve.summary)
        if not matched_words or any(word in components for word in matched_words):
            filtered_cves[cve_id] = cve

    num_deleted = len(cves) - len(filtered_cves)
    if num_deleted > 0:
        logging.debug(f'{file_path}: Deleted {num_deleted} CVEs with components not found in this BusyBox binary')

    return filtered_cves


def get_matched_words(cve_data: str) -> list[str]:
    """
    Gets the matched words in the provided CVE description.
    """
    matched_words = []
    for pattern in PATTERNS_1 + PATTERNS_2:
        match = pattern.search(cve_data)
        if match:
            matched_words.append(match.group())

    return matched_words
