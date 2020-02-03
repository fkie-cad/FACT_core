from typing import Iterable, List, T, Tuple


def remove_duplicates_from_unhashable(unhashable_list: List[T]) -> List[T]:
    result = []
    for element in unhashable_list:
        if element not in result:
            result.append(element)
    return result


def remove_duplicates_from_list(list_):
    return list(set(list_))


def substring_is_in_list(string: str, substring_list: List[str]) -> bool:
    return any(substring in string for substring in substring_list)


def iter_element_and_rest(iterable: Iterable[T]) -> Tuple[T, Iterable[T]]:
    for element in iterable:
        rest = [e for e in iterable if e != element]
        yield element, rest
