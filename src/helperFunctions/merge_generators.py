import itertools

from copy import deepcopy
from itertools import zip_longest
from random import sample, seed
from typing import Sequence

seed()


def _add_nested_list_to_dict(input_list, input_dict):
    for item in input_list:
        if item[0][0] in input_dict.keys():
            input_dict[item[0][0]] += item[1]
        else:
            input_dict[item[0][0]] = item[1]
    return input_dict


def sum_up_lists(list_a, list_b):
    '''
    This function sums up the entries of two chart lists
    '''
    tmp = {}
    for key, value in itertools.chain(list_a, list_b):
        tmp.setdefault(key, 0)
        tmp[key] += value

    return [[k, v] for k, v in tmp.items()]


def sum_up_nested_lists(list_a, nested_list_b):
    '''
    This function sums up the entries of two nested chart lists
    '''
    tmp = {}
    _add_nested_list_to_dict(list_a, tmp)
    _add_nested_list_to_dict(nested_list_b, tmp)

    return [[k, v] for k, v in tmp.items()]


def merge_dict(d1, d2):
    '''
    Merges d1 with d2 and returns the result.

    :return: A new dictionary containing d1 merged with d2
    '''
    if d1 is None or d2 is None:
        return d1 or d2
    result = deepcopy(d1)
    result.update(d2)
    return result


def avg(seq: Sequence[float]) -> float:
    '''
    Returns the average of seq.
    '''
    if len(seq) == 0:
        return 0
    return sum(seq) / len(seq)


def shuffled(sequence):
    '''
    Copies and shuffles an array.

    :param sequence: The array to be shuffled
    :return: A shuffled copy of `sequence`
    '''
    return sample(sequence, len(sequence))
