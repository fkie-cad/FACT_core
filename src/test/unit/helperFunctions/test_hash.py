from pathlib import Path

from helperFunctions.hash import (
    get_imphash, get_md5, get_sha256, get_ssdeep, get_ssdeep_comparison, normalize_lief_items
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


def test_get_ssdeep_comparison():
    factor = get_ssdeep_comparison('192:3xaGk2v7RNOrG4D9tVwTiGTUwMyKP3JDddt2vT3GiH3gnK:BHTWy66gnK', '192:3xaGk2v7RNOrG4D9tVwTiGTUwMyKP3JDddt2vT3GK:B')
    assert factor == 96, 'ssdeep similarity seems to be out of shape'


def test_imphash():
    fo = create_test_file_object(bin_path=str(Path(get_test_data_dir(), 'test_executable')))
    fo.processed_analysis = {'file_type': {'mime': 'application/x-executable'}}
    imphash = get_imphash(fo)
    assert isinstance(imphash, str), 'imphash should be a string'
    assert len(imphash) == 32, 'imphash does not seem to be an md5'


def test_imphash_bad_file():
    fo = create_test_file_object()
    fo.processed_analysis = {'file_type': {'mime': 'application/x-executable'}}
    assert not get_imphash(fo)


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
