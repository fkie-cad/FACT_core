from web_interface.components.hex_highlighting import preview_data_as_hex


def test_hex_preview_merge():
    test_input = b'\x01abc\x02\x00\xff\x00\x03'
    highlighted = preview_data_as_hex(test_input, chunk_size=16)
    assert highlighted.count('<span') == 4, 'highlight zones should be merged'


def test_hex_preview_data_rows():
    test_input = b'abc1\x00\x00\xff\x01\x02'
    highlighted = preview_data_as_hex(test_input, chunk_size=4)
    assert highlighted.count('\n') == 4  # 2 header lines and 3 rows (len(input) // 4)
    assert (
        len(highlighted.split('\n')[-1].split('|')[2]) == 14
    ), 'partial rows should be filled up'  # pylint: disable=use-maxsplit-arg
