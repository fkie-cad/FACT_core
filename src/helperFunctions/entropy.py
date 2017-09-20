from collections import Counter
import random
import logging
import sys
from math import log


def gtest_value(frequencies):
    """
    calculates the gtest metric for a list of frequencies
    """
    elements = sum(frequencies)
    g = 0
    for frequency in frequencies:
        if frequency > 0:
            try:
                g += frequency * log(frequency / (elements / 256))
            except Exception as e:
                logging.error("Could not calculate g_test element: {} {}".format(sys.exc_info()[0].__name__, e))
        else:
            g += frequency
    return 2 * g


def chi2_value(frequencies):
    """
    calculates the chi² metric for a list of frequencies
    """
    elements = sum(frequencies)
    chi = 0
    for frequency in frequencies:
        try:
            chi += (((elements / 256) - frequency) ** 2) / (elements / 256)
        except Exception as e:
            logging.error("Could not calculate chi_square element: {} {}".format(sys.exc_info()[0].__name__, e))
    return chi


def generate_random_data(size=32, seed=None):
    """
    generates a random byte string
    """
    random.seed(seed)
    random_data = random.getrandbits(size * 8).to_bytes(size, 'little')
    return random_data


def get_frequencies(block):
    """
    calculates the frequency of byte-values in a block of data
    """
    frequencies = [0] * 256
    counted = Counter(block)
    for bitvalue in block:
        frequencies[bitvalue] = counted[bitvalue]
    return frequencies
