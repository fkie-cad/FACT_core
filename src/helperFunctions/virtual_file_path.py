from typing import List


def split_virtual_path(virtual_path: str) -> List[str]:
    return [element for element in virtual_path.split('|') if element]


def join_virtual_path(*elements: str) -> str:
    return '|'.join(elements)


def get_base_of_virtual_path(virtual_path: str) -> str:
    return join_virtual_path(*split_virtual_path(virtual_path)[:-1])


def get_top_of_virtual_path(virtual_path: str) -> str:
    if not virtual_path:
        return virtual_path
    return split_virtual_path(virtual_path)[-1]
