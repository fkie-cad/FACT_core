from time import time

import pytest

from storage.schema import ComparisonEntry
from test.common_helper import create_test_firmware, generate_analysis_entry
from test.integration.storage.helper import create_fw_with_child_fo


def test_comparison_exists(comparison_db, backend_db):
    comp_id = 'uid1;uid2'
    assert comparison_db.comparison_exists(comp_id) is False
    _add_comparison(comparison_db, backend_db)
    assert comparison_db.comparison_exists(comp_id) is True


def test_add_and_get_comparison_result(comparison_db, backend_db):
    fw_one, _, _, compare_id = _add_comparison(comparison_db, backend_db)
    retrieved = comparison_db.get_comparison_result(compare_id)
    assert retrieved['general']['virtual_file_path'][fw_one.uid] == 'dev_one_name', 'content of retrieval not correct'


def test_get_not_existing_result(comparison_db, backend_db):
    fw_one, fw_two, _, compare_id = _create_comparison()
    backend_db.insert_multiple_objects(fw_one, fw_two)
    result = comparison_db.get_comparison_result(compare_id)
    assert result is None


def test_calculate_comparison_id(comparison_db):
    _, _, compare_dict, compare_id = _create_comparison()
    comp_id = comparison_db._calculate_comp_id(compare_dict)
    assert comp_id == compare_id


def test_comp_id_incomplete_entries(comparison_db):
    compare_dict = {'general': {'stat_1': {'a': None}, 'stat_2': {'b': None}}}
    comp_id = comparison_db._calculate_comp_id(compare_dict)
    assert comp_id == 'a;b'


def test_get_latest_comparisons(backend_db, comparison_db):
    before = time()
    fw_one, fw_two, _, _ = _add_comparison(comparison_db, backend_db)
    result = comparison_db.page_comparison_results(limit=10)
    for comparison_id, hid, submission_date in result:
        assert fw_one.uid in hid
        assert fw_two.uid in hid
        assert fw_one.uid in comparison_id
        assert fw_two.uid in comparison_id
        assert before <= submission_date <= time()


def test_delete_fw_cascades_to_comp(backend_db, comparison_db, admin_db):
    _, fw_two, _, comp_id = _add_comparison(comparison_db, backend_db)

    with comparison_db.get_read_only_session() as session:
        assert session.get(ComparisonEntry, comp_id) is not None

    admin_db.delete_firmware(fw_two.uid)

    with comparison_db.get_read_only_session() as session:
        assert session.get(ComparisonEntry, comp_id) is None, 'deletion should be cascaded if one FW is deleted'


def test_get_latest_removed_firmware(comparison_db, backend_db, admin_db):
    fw_one, fw_two, compare_dict, _ = _create_comparison()
    backend_db.insert_multiple_objects(fw_one, fw_two)
    comparison_db.add_comparison_result(compare_dict)

    result = comparison_db.page_comparison_results(limit=10)
    assert result != [], 'A compare result should be available'

    admin_db.delete_firmware(fw_two.uid)

    result = comparison_db.page_comparison_results(limit=10)

    assert result == [], 'No compare result should be available'


def test_get_total_number_of_results(comparison_db, backend_db):
    _add_comparison(comparison_db, backend_db)

    number = comparison_db.get_total_number_of_results()
    assert number == 1, 'no compare result found in database'


@pytest.mark.parametrize(
    ('root_uid', 'expected_result'),
    [
        ('the_root_uid', ['uid1', 'uid2']),
        ('some_other_uid', []),
        (None, []),
    ],
)
def test_get_exclusive_files(comparison_db, backend_db, root_uid, expected_result):
    fw_one, fw_two, compare_dict, comp_id = _create_comparison()
    compare_dict['plugins'] = {'File_Coverage': {'exclusive_files': {'the_root_uid': ['uid1', 'uid2']}}}
    backend_db.insert_multiple_objects(fw_one, fw_two)
    comparison_db.add_comparison_result(compare_dict)
    exclusive_files = comparison_db.get_exclusive_files(comp_id, root_uid)
    assert exclusive_files == expected_result


def test_get_vfp_of_included_text_files(backend_db, comparison_db):
    fo, fw = create_fw_with_child_fo()
    fo.processed_analysis['file_type'] = generate_analysis_entry(analysis_result={'mime': 'text/plain'})
    backend_db.insert_multiple_objects(fw, fo)
    result = comparison_db.get_vfp_of_included_text_files(fw.uid, [])
    assert result == {'/folder/testfile1': {fo.uid}}


def _create_comparison(uid1='uid1', uid2='uid2'):
    fw_one = create_test_firmware()
    fw_one.uid = uid1
    fw_two = create_test_firmware()
    fw_two.set_binary(b'another firmware')
    fw_two.uid = uid2
    compare_dict = {
        'general': {
            'hid': {fw_one.uid: 'foo', fw_two.uid: 'bar'},
            'virtual_file_path': {fw_one.uid: 'dev_one_name', fw_two.uid: 'dev_two_name'},
        },
        'plugins': {},
    }
    compare_id = f'{fw_one.uid};{fw_two.uid}'
    return fw_one, fw_two, compare_dict, compare_id


def _add_comparison(comparison_db, backend_db, uid1='uid1', uid2='uid2'):
    fw_one, fw_two, compare_dict, comparison_id = _create_comparison(uid1=uid1, uid2=uid2)
    backend_db.insert_multiple_objects(fw_one, fw_two)
    comparison_db.add_comparison_result(compare_dict)
    return fw_one, fw_two, compare_dict, comparison_id
