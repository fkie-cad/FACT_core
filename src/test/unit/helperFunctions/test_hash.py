from collections import namedtuple
from pathlib import Path

from helperFunctions.fileSystem import get_test_data_dir
from helperFunctions.hash import (
    _normalize_functions, check_similarity_of_sets, get_imphash, get_md5, get_sha256, get_ssdeep, get_ssdeep_comparison
)
from test.common_helper import create_test_file_object

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


def test_check_similarity_of_sets():
    pairs = [{0, 1}, {2, 3}, {4, 8}, {1, 8}, {3, 4}, {0, 8}]
    pair_one = [{0, 8}, {1, 8}]
    pair_two = [{2, 3}, {3, 4}]
    assert check_similarity_of_sets(pair_one, pairs), 'set simililarity does not work correctly'
    assert not check_similarity_of_sets(pair_two, pairs), 'set simililarity does not work correctly'


def test_imphash():
    fo = create_test_file_object(bin_path=str(Path(get_test_data_dir(), 'test_executable')))
    fo.processed_analysis = {'file_type': {'mime': 'application/x-executable'}}
    assert get_imphash(fo) == '80a89f1e3f70b5c421528509ae74503c', 'imphash computation is off'


def test_imphash_bad_file():
    fo = create_test_file_object()
    fo.processed_analysis = {'file_type': {'mime': 'application/x-executable'}}
    assert not get_imphash(fo)


def test_normalize_items_from_strings():
    functions = ['printf', '__libc_start_main']
    assert _normalize_functions(functions) == functions


def test_normalize_items_from_objects():
    Function = namedtuple('Function', ['name'])
    functions = ['printf', '__libc_start_main']
    assert _normalize_functions([Function(name) for name in functions]) == functions


def test_normalize_items_bad_objects():
    assert _normalize_functions([None, None]) == []


def test_normalize_items_empty_list():
    assert _normalize_functions([]) == []
