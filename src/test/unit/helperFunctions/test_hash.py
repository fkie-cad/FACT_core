from helperFunctions.hash import (
    get_md5,
    get_sha256,
)

TEST_STRING = 'test string'
TEST_SHA256 = 'd5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b'
TEST_MD5 = '6f8db599de986fab7a21625b7916589c'


def test_get_sha256():
    assert get_sha256(TEST_STRING) == TEST_SHA256, 'not correct from string'


def test_get_md5():
    assert get_md5(TEST_STRING) == TEST_MD5, 'not correct from string'
