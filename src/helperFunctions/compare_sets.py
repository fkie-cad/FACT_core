from typing import Iterable, Iterator, List, Tuple, TypeVar

# Generics (not intended for export)
_T = TypeVar('_T')


def remove_duplicates_from_unhashable(unhashable_list: List[_T]) -> List[_T]:
    '''
    Remove duplicates from a list of unhashable objects (meaning converting to a set and back won't work).

    :param unhashable_list: the list of unhashable objects
    :return: list of unique items
    '''
    result = []
    for element in unhashable_list:
        if element not in result:
            result.append(element)
    return result


def remove_duplicates_from_list(list_):
    '''
    Remove duplicates from a list (by converting it to a set and back).

    .. caution::
        Only works with lists of hashable objects!

    :param list_: the input list (possibly) containing duplicates
    :return: a new list only containing unique elements
    '''
    return list(set(list_))


def substring_is_in_list(string: str, substring_list: List[str]) -> bool:
    '''
    Check if any element in a list of strings is a substring of the provided string.

    :param string: the string that is checked if it contains any of the substrings
    :param substring_list: a list of possible substrings
    :return: true if a substring is found and false otherwise
    '''
    return any(substring in string for substring in substring_list)


def iter_element_and_rest(iterable: Iterable[_T]) -> Iterator[Tuple[_T, Iterable[_T]]]:
    '''
    Iterate over each element of an iterable object (e.g. a list) and also get all other (remaining) elements
    from the object.

    :param iterable: the object that will be iterated over
    :return: a generator with tuples containing the item and the rest (all other elements)
    '''
    for element in iterable:
        rest = [e for e in iterable if e != element]
        yield element, rest
