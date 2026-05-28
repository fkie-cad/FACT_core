import pytest

from web_interface.components.ajax_routes import AjaxRoutes


@pytest.mark.parametrize(
    ('candidate', 'comparison_id', 'expected_result'),
    [
        ('all', 'uid1;uid2', 'uid1'),
        ('uid1', 'uid1;uid2', 'uid1'),
        ('uid2', 'uid1;uid2', 'uid2'),
        ('all', 'uid1', 'uid1'),
    ],
)
def test_get_root_uid(candidate, comparison_id, expected_result):
    assert AjaxRoutes._get_root_uid(candidate, comparison_id) == expected_result
