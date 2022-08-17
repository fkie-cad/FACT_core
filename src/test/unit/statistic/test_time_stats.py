import pytest

from statistic.time_stats import _build_time_dict, _fill_in_time_gaps


def test_build_time_dict():
    test_input = [(2016, 12, 10), (2017, 1, 8)]
    expected_result = {2016: {12: 10}, 2017: {1: 8}}
    assert _build_time_dict(test_input) == expected_result


@pytest.mark.parametrize(
    'input_data, expected',
    [
        ({}, {}),
        ({
            2016: {
                1: 1, 4: 4
            }
        }, {
            2016: {
                1: 1, 2: 0, 3: 0, 4: 4
            }
        }),
        ({
            2000: {
                12: 1
            }, 2001: {
                2: 1
            }
        }, {
            2000: {
                12: 1
            }, 2001: {
                1: 0, 2: 1
            }
        }),
        ({
            2000: {
                11: 1
            }, 2001: {
                1: 1
            }
        }, {
            2000: {
                11: 1, 12: 0
            }, 2001: {
                1: 1
            }
        }),
    ],
)
def test_fill_in_time_gaps(input_data, expected):
    _fill_in_time_gaps(input_data)
    assert input_data == expected
