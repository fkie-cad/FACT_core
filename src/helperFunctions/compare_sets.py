from copy import deepcopy
from typing import List

from helperFunctions.dataConversion import list_of_lists_to_list_of_sets


def intersection_of_list_of_lists(list_of_lists):
    tmp = list_of_lists_to_list_of_sets(list_of_lists)
    return list(intersection_of_list_of_sets(tmp))


def intersection_of_list_of_sets(list_of_sets):
    if len(list_of_sets) == 0:
        return set()
    else:
        tmp = list_of_sets.pop()
        for item in list_of_sets:
            tmp = tmp.intersection(item)
        return tmp


def difference_of_lists(base_list, list_of_other_lists):
    list_of_other_sets = list_of_lists_to_list_of_sets(list_of_other_lists)
    return list(difference_of_sets(set(base_list), list_of_other_sets))


def difference_of_sets(base_set, list_of_other_sets):
    tmp = base_set
    for item in list_of_other_sets:
        tmp = tmp.difference(item)
    return tmp


def remove_duplicates_from_list_of_lists(main_list):
    for item in main_list:
        item.sort()
    for primary_pointer, _ in enumerate(main_list):
        for secondary_pointer, _ in enumerate(main_list):
            if main_list[primary_pointer] == main_list[secondary_pointer] and not primary_pointer == secondary_pointer:
                main_list[secondary_pointer] = None
    main_list = remove_all(main_list, None)
    return main_list


def collapse_pair_of_sets(pair_of_sets):
    result = deepcopy(pair_of_sets[0])
    result.update(pair_of_sets[1])
    return result


def index_of_other_list_including_item(list_of_lists, item, start_index):
    for index in range(start_index + 1, len(list_of_lists)):
        if item in list_of_lists[index]:
            return index
    return -1


def remove_all(set_or_list, item):
    while item in set_or_list:
        set_or_list.remove(item)
    return set_or_list


def make_pairs_of_sets(list_of_sets):
    pairs = []
    for first_set in list_of_sets:
        for second_set in list_of_sets:
            if first_set != second_set:
                if (first_set, second_set) not in pairs:
                    pairs.append((first_set, second_set))
    return pairs


def safely_remove_pair_of_sets(list_of_sets, pair_of_sets):
    if pair_of_sets[0] in list_of_sets:
        list_of_sets.remove(pair_of_sets[0])
    if pair_of_sets[1] in list_of_sets:
        list_of_sets.remove(pair_of_sets[1])


def remove_duplicates_from_list(l):
    return list(set(l))


def substring_is_in_list(s: str, substring_list: List[str]) -> bool:
    return any(substring in s for substring in substring_list)
