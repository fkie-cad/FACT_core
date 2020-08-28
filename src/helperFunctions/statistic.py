import logging
import re
import sys
from contextlib import suppress
from typing import Any


def calculate_total_files(list_of_stat_tuples):
    total_amount_of_files = 0
    for item in list_of_stat_tuples:
        with suppress(IndexError):
            total_amount_of_files += item[0][1]
    return total_amount_of_files


def is_sanitized_entry(entry: Any) -> bool:
    '''
    Check a database entry if it was sanitized (meaning the database entry was too large for the MongoDB database and
    was swapped to the file system).

    :param entry: A database entry.
    :return: `True` if the entry is sanitized and `False` otherwise.
    '''
    try:
        if re.search(r'_[0-9a-f]{64}_[0-9]+', entry) is None:
            return False
        return True
    except TypeError:  # DB entry has type other than string (e.g. integer or float)
        return False
    except Exception as e_type:
        logging.error('Could not determine entry sanitization state: {} {}'.format(sys.exc_info()[0].__name__, e_type))
        return False
