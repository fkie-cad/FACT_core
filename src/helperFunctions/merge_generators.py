from __future__ import annotations

from collections.abc import Sequence
from random import sample, seed
from typing import TypeVar

seed()

T = TypeVar('T')


def shuffled(sequence: Sequence[T]) -> list[T]:
    """
    Copies and shuffles an array.

    :param sequence: The array to be shuffled
    :return: A shuffled copy of `sequence`
    """
    return sample(sequence, len(sequence))
