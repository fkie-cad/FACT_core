import os

from helperFunctions.hash import (
    _suppress_stdout,
    get_imphash,
    get_md5,
    get_sha256,
    get_ssdeep,
    get_tlsh,
    normalize_lief_items,
)
from test.common_helper import create_test_file_object, get_test_data_dir

TEST_STRING = 'test string'
TEST_SHA256 = 'd5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b'
TEST_MD5 = '6f8db599de986fab7a21625b7916589c'
TEST_SSDEEP = '3:Hv2:HO'


def test_get_sha256():
    assert get_sha256(TEST_STRING) == TEST_SHA256, 'not correct from string'


def test_get_md5():
    assert get_md5(TEST_STRING) == TEST_MD5, 'not correct from string'


def test_get_ssdeep():
    assert get_ssdeep(TEST_STRING) == TEST_SSDEEP, 'not correct from string'


def test_imphash():
    fo = create_test_file_object(bin_path=str(get_test_data_dir() / 'test_executable'))
    fo.processed_analysis = {'file_type': {'result': {'mime': 'application/x-executable'}}}
    imphash = get_imphash(fo)
    assert isinstance(imphash, str), 'imphash should be a string'
    assert len(imphash) == 32, 'imphash does not seem to be an md5'


def test_imphash_bad_file():
    fo = create_test_file_object()
    fo.processed_analysis = {'file_type': {'result': {'mime': 'application/x-executable'}}}
    assert get_imphash(fo) is None


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


def print_foo():
    print('foo', end='')  # noqa: T201


def test_suppress_stdout(capsys):
    print_foo()

    without_decorator = capsys.readouterr()
    assert without_decorator.out == 'foo'

    with _suppress_stdout():
        print_foo()

    with_decorator = capsys.readouterr()
    assert not with_decorator.out


def test_get_tlsh():
    assert get_tlsh(b'foobar') == ''  # make sure the result is not 'TNULL'
    assert get_tlsh(os.urandom(2**7)) != ''  # the new tlsh version should work for smaller inputs
