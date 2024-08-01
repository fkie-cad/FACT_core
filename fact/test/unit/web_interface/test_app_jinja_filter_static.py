import pytest

from fact.web_interface.components.jinja_filter import FilterClass


def test_split_user_and_password_type_entry():
    new_test_entry_form = {'test:mosquitto': {'password': '123456'}}
    old_test_entry_form = {'test': {'password': '123456'}}
    expected_new_entry = {'test': {'mosquitto': {'password': '123456'}}}
    expected_old_entry = {'test': {'unix': {'password': '123456'}}}
    assert expected_new_entry == FilterClass._split_user_and_password_type_entry(new_test_entry_form)
    assert expected_old_entry == FilterClass._split_user_and_password_type_entry(old_test_entry_form)


@pytest.mark.parametrize(
    ('hid', 'uid', 'current_uid', 'expected_output'),
    [
        ('hid', 'uid', 'uid', 'badge-secondary">hid'),
        ('hid', 'uid', 'different_uid', 'badge-primary">    <a'),
        (
            'suuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuper/long/human_readable_id',
            'uid',
            'uid',
            '~uuuuuuuuuuuuuuuuuuuuuuuuuuuuper/long/human_readable_id',
        ),
    ],
)
def test_virtual_path_element_to_span(hid, uid, current_uid, expected_output):
    assert expected_output in FilterClass._virtual_path_element_to_span(hid, uid, 'root_uid', current_uid)


class FilterClassMock:
    @staticmethod
    def _get_chart_element_count():
        return 10


@pytest.mark.parametrize(
    ('input_data', 'limit', 'expected_result'),
    [
        (
            [('NX enabled', 1696), ('NX disabled', 207), ('Canary enabled', 9)],
            None,
            {
                'labels': ['NX enabled', 'NX disabled', 'Canary enabled'],
                'datasets': [
                    {
                        'data': [1696, 207, 9],
                        'backgroundColor': ['#4062fa', '#149df1', '#18cde4'],
                        'borderColor': '#fff',
                        'borderWidth': 2,
                    }
                ],
            },
        ),
        (
            [('NX enabled', 1696), ('NX disabled', 207), ('Canary enabled', 9)],
            2,
            {
                'labels': ['NX enabled', 'NX disabled', 'rest'],
                'datasets': [
                    {
                        'data': [1696, 207, 9],
                        'backgroundColor': ['#4062fa', '#a0faa1'],
                        'borderColor': '#fff',
                        'borderWidth': 2,
                    }
                ],
            },
        ),
        ([()], None, None),
    ],
)
def test_data_to_chart_limited(input_data, limit, expected_result):
    result = FilterClass.data_to_chart_limited(FilterClassMock(), input_data, limit=limit)
    assert result == expected_result
