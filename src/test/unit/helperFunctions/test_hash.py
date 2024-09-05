from helperFunctions.hash import (
    get_md5,
    get_sha256,
    normalize_lief_items,
)

TEST_STRING = 'test string'
TEST_SHA256 = 'd5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b'
TEST_MD5 = '6f8db599de986fab7a21625b7916589c'


def test_get_sha256():
    assert get_sha256(TEST_STRING) == TEST_SHA256, 'not correct from string'


def test_get_md5():
    assert get_md5(TEST_STRING) == TEST_MD5, 'not correct from string'


def test_normalize_items_from_strings():
    functions = ['printf', '__libc_start_main']
    assert normalize_lief_items(functions) == functions


def test_normalize_items_from_objects():
    class Function:
        def __init__(self, name):
            self.name = name

        def __str__(self):
            return self.name

    functions = ['printf', '__libc_start_main']
    assert normalize_lief_items([Function(name) for name in functions]) == functions


def test_normalize_items_empty_list():
    assert normalize_lief_items([]) == []
