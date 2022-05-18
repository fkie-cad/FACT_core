from random import sample, seed
from typing import Sequence, TypeVar

seed()
T = TypeVar('T')  # pylint: disable=invalid-name


def _add_nested_list_to_dict(input_list, input_dict):
    for item in input_list:
        if item[0][0] in input_dict.keys():
            input_dict[item[0][0]] += item[1]
        else:
            input_dict[item[0][0]] = item[1]
    return input_dict


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
