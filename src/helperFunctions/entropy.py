import random


def generate_random_data(size=32, seed=None):
    """
    generates a random byte string
    """
    random.seed(seed)
    random_data = random.getrandbits(size * 8).to_bytes(size, 'little')
    return random_data
