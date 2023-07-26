import re
import logging
from pathlib import Path

from .database.schema import Cve
from objects.file import FileObject

GROUP_1 = None
GROUP_2 = None


def filter_busybox_cves(file_object: FileObject, cves: list[Cve]) -> list[Cve]:
    """
    Filters the BusyBox CVEs based on the components present in the binary file and the specified version.
    """
    components = get_busybox_components(file_object)
    return filter_cves_by_component(cves, components)


def get_busybox_components(file_object: FileObject) -> list[str]:
    """
    Extracts the BusyBox components from the binary file.
    """
    file_path = Path(file_object.file_path)
    with file_path.open(mode='rb') as f:
        data = f.read()

    start_index = data.index(b'\x5b\x00\x5b\x5b\x00')
    end_index = data.index(b'\x00\x00', start_index + 5)
    extracted_bytes = data[start_index : end_index + 2]
    split_bytes = extracted_bytes.split(b'\x00')
    return [word.decode('ascii') for word in split_bytes if word]


def filter_cves_by_component(cves: list[Cve], components: list[str]) -> list[Cve]:
    """
    Filters CVEs based on the components present in the BusyBox binary file.
    """
    filtered_cves = []
    for cve in cves:
        matched_words = get_matched_words(cve.summary)
        if matched_words:
            if any(word in components for word in matched_words):
                filtered_cves.append(cve)
        else:
            filtered_cves.append(cve)

    num_deleted = len(cves) - len(filtered_cves)
    if num_deleted > 0:
        logging.info(f'Deleted {num_deleted} CVEs with components not found in this BusyBox binary')

    return filtered_cves


def get_matched_words(cve_data: str) -> list[str]:
    """
    Gets the matched words in the provided CVE description.
    """
    global GROUP_1, GROUP_2

    if GROUP_1 is None or GROUP_2 is None:
        group_1_path = Path(__file__).parent / 'group_1.txt'
        group_2_path = Path(__file__).parent / 'group_2.txt'
        with group_1_path.open('r') as f1, group_2_path.open('r') as f2:
            GROUP_1 = f1.read().splitlines()
            GROUP_2 = f2.read().splitlines()

    pattern_1 = r'(?:\")(?:\-|\")'
    pattern_2 = r'(?:\b|\(|\"|\_)(?:{})(?:\b|\)|-)'

    return [word for word in GROUP_1 if re.search(pattern_1.format(word), cve_data)] + [
        word for word in GROUP_2 if re.search(pattern_2.format(word), cve_data)
    ]
