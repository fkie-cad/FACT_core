from copy import deepcopy
from itertools import zip_longest
from random import sample, seed
from typing import Sequence

seed()


def merge_generators(*generators):
    for values in zip_longest(*generators):
        for value in values:
            if value is not None:
                yield value


def _add_list_to_dict(input_list, input_dict):
    for item in input_list:
        if item[0] in input_dict.keys():
            input_dict[item[0]] += item[1]
        else:
            input_dict[item[0]] = item[1]
    return input_dict


def _add_nested_list_to_dict(input_list, input_dict):
    for item in input_list:
        if item[0][0] in input_dict.keys():
            input_dict[item[0][0]] += item[1]
        else:
            input_dict[item[0][0]] = item[1]
    return input_dict


def _convert_dict_to_chart_list(input_dict):
    tmp = []
    for item in input_dict.keys():
        tmp.append([item, input_dict[item]])
    return tmp


def sum_up_lists(list_a, list_b):
    '''
    This function sums up the entries of two chart lists
    '''
    tmp = {}
    _add_list_to_dict(list_a, tmp)
    _add_list_to_dict(list_b, tmp)
    return _convert_dict_to_chart_list(tmp)


def sum_up_nested_lists(list_a, nested_list_b):
    '''
    This function sums up the entries of two nested chart lists
    '''
    tmp = {}
    _add_nested_list_to_dict(list_a, tmp)
    _add_nested_list_to_dict(nested_list_b, tmp)
    return _convert_dict_to_chart_list(tmp)


def merge_dict(d1, d2):
    if d1 is None or d2 is None:
        return d1 or d2
    result = deepcopy(d1)
    result.update(d2)
    return result


def avg(list_: Sequence[float]) -> float:
    if len(list_) == 0:
        return 0
    return sum(list_) / len(list_)


def shuffled(sequence):
    return sample(sequence, len(sequence))
