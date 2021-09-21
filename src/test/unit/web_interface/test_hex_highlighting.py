import pytest

from web_interface.components.hex_highlighting import highlight_hex


@pytest.mark.parametrize('test_input, expected_output', [
    (
        ' 61 62 63 ',  # abc
        ' <span class="hljs-number">61</span> <span class="hljs-number">62</span> <span class="hljs-number">63</span> '
    ),
    (
        ' 00 31 FF ',  # \x00 1 \xff
        ' <span class="hljs-comment">00</span> <span class="hljs-built_in">31</span> <span class="hljs-comment">FF</span> '
    ),
    (
        ' F0 D3 01 ',
        ' <span class="hljs-keyword">F0</span> <span class="hljs-keyword">D3</span> 01 '
    ),
])
def test_highlight_hex(test_input, expected_output):
    assert highlight_hex(test_input) == expected_output
