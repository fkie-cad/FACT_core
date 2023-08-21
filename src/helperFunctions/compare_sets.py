from __future__ import annotations

from typing import TypeVar, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

# Generics (not intended for export)
_T = TypeVar('_T')


def _remove_duplicates_from_unhashable(unhashable_list: list[_T]) -> list[_T]:
    """
    Remove duplicates from a list of unhashable objects (meaning converting to a set and back won't work).

    :param unhashable_list: A list of unhashable objects.
    :return: A list of unique items.
    """
    result = []
    for element in unhashable_list:
        if element not in result:
            result.append(element)
    return result


def remove_duplicates_from_list(list_: list[_T]) -> list[_T]:
    """
    Remove duplicates from a list.

    :param list_: The input list (possibly) containing duplicates.
    :return: A new list only containing unique elements.
    """
    try:
        return list(set(list_))
    except TypeError:
        return _remove_duplicates_from_unhashable(list_)


def substring_is_in_list(string: str, substring_list: list[str]) -> bool:
    """
    Check if any element in a list of strings is a substring of the provided string.

    :param string: The string that is checked if it contains any of the substrings.
    :param substring_list: A list of possible substrings.
    :return: `True` if a substring is found and `False` otherwise.
    """
    return any(substring in string for substring in substring_list)


def iter_element_and_rest(iterable: Iterable[_T]) -> Iterator[tuple[_T, list[_T]]]:
    """
    Iterate over each element of an iterable object (e.g. a list) and also get all other (remaining) elements
    from the object.

    :param iterable: The object that will be iterated over.
    :return: A generator with tuples containing the item and the rest (all other elements).
    """
    for element in iterable:
        yield element, [e for e in iterable if e != element]
