# pylint: disable=attribute-defined-outside-init,protected-access
from time import time

import pytest

from storage.schema import ComparisonEntry
from test.common_helper import create_test_firmware  # pylint: disable=wrong-import-order


def test_comparison_exists(db, comp_db):
    comp_id = 'uid1;uid2'
    assert comp_db.comparison_exists(comp_id) is False
    _add_comparison(comp_db, db)
    assert comp_db.comparison_exists(comp_id) is True


def test_add_and_get_comparison_result(db, comp_db):
    fw_one, _, _, compare_id = _add_comparison(comp_db, db)
    retrieved = comp_db.get_comparison_result(compare_id)
    assert retrieved['general']['virtual_file_path'][fw_one.uid] == 'dev_one_name', 'content of retrieval not correct'


def test_get_not_existing_result(db, comp_db):
    fw_one, fw_two, _, compare_id = _create_comparison()
    db.backend.add_object(fw_one)
    db.backend.add_object(fw_two)
    result = comp_db.get_comparison_result(compare_id)
    assert result is None


def test_calculate_comparison_id(db, comp_db):  # pylint: disable=unused-argument
    _, _, compare_dict, compare_id = _create_comparison()
    comp_id = comp_db._calculate_comp_id(compare_dict)
    assert comp_id == compare_id


def test_comp_id_incomplete_entries(db, comp_db):  # pylint: disable=unused-argument
    compare_dict = {'general': {'stat_1': {'a': None}, 'stat_2': {'b': None}}}
    comp_id = comp_db._calculate_comp_id(compare_dict)
    assert comp_id == 'a;b'


def test_get_latest_comparisons(db, comp_db):
    before = time()
    fw_one, fw_two, _, _ = _add_comparison(comp_db, db)
    result = comp_db.page_comparison_results(limit=10)
    for comparison_id, hid, submission_date in result:
        assert fw_one.uid in hid
        assert fw_two.uid in hid
        assert fw_one.uid in comparison_id
        assert fw_two.uid in comparison_id
        assert before <= submission_date <= time()


def test_delete_fw_cascades_to_comp(db, comp_db):
    _, fw_two, _, comp_id = _add_comparison(comp_db, db)

    with comp_db.get_read_only_session() as session:
        assert session.get(ComparisonEntry, comp_id) is not None

    db.admin.delete_firmware(fw_two.uid)

    with comp_db.get_read_only_session() as session:
        assert session.get(ComparisonEntry, comp_id) is None, 'deletion should be cascaded if one FW is deleted'


def test_get_latest_removed_firmware(db, comp_db):
    fw_one, fw_two, compare_dict, _ = _create_comparison()
    db.backend.add_object(fw_one)
    db.backend.add_object(fw_two)
    comp_db.add_comparison_result(compare_dict)

    result = comp_db.page_comparison_results(limit=10)
    assert result != [], 'A compare result should be available'

    db.admin.delete_firmware(fw_two.uid)

    result = comp_db.page_comparison_results(limit=10)

    assert result == [], 'No compare result should be available'


def test_get_total_number_of_results(db, comp_db):
    _add_comparison(comp_db, db)

    number = comp_db.get_total_number_of_results()
    assert number == 1, 'no compare result found in database'


@pytest.mark.parametrize(
    'root_uid, expected_result', [
        ('the_root_uid', ['uid1', 'uid2']),
        ('some_other_uid', []),
        (None, []),
    ]
)
def test_get_exclusive_files(db, comp_db, root_uid, expected_result):
    fw_one, fw_two, compare_dict, comp_id = _create_comparison()
    compare_dict['plugins'] = {'File_Coverage': {'exclusive_files': {'the_root_uid': ['uid1', 'uid2']}}}

    db.backend.add_object(fw_one)
    db.backend.add_object(fw_two)
    comp_db.add_comparison_result(compare_dict)
    exclusive_files = comp_db.get_exclusive_files(comp_id, root_uid)
    assert exclusive_files == expected_result


def _create_comparison(uid1='uid1', uid2='uid2'):
    fw_one = create_test_firmware()
    fw_one.uid = uid1
    fw_two = create_test_firmware()
    fw_two.set_binary(b'another firmware')
    fw_two.uid = uid2
    compare_dict = {
        'general': {
            'hid': {
                fw_one.uid: 'foo', fw_two.uid: 'bar'
            },
            'virtual_file_path': {
                fw_one.uid: 'dev_one_name', fw_two.uid: 'dev_two_name'
            },
        },
        'plugins': {},
    }
    compare_id = f'{fw_one.uid};{fw_two.uid}'
    return fw_one, fw_two, compare_dict, compare_id


def _add_comparison(comp_db, db, uid1='uid1', uid2='uid2'):
    fw_one, fw_two, compare_dict, comparison_id = _create_comparison(uid1=uid1, uid2=uid2)
    db.backend.add_object(fw_one)
    db.backend.add_object(fw_two)
    comp_db.add_comparison_result(compare_dict)
    return fw_one, fw_two, compare_dict, comparison_id
