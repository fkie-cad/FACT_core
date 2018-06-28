from helperFunctions.sort import sort_nice_data_list_by_virtual_path, set_root_uids


def test_sort_fo_list_by_virtual_path():
    a = {'virtual_file_paths': ['/a/foobar']}
    b = {'virtual_file_paths': ['/b/foobar']}
    c = {'virtual_file_paths': ['/c/foobar']}
    test_list = [c, b, a]
    assert sort_nice_data_list_by_virtual_path(test_list, 'root_uid') == [a, b, c]


def test_set_root_uids():
    root_uid = 'root'
    test_input = [
        {'virtual_file_paths': ['/a/foobar'], 'root_uid': 'foo'},
        {'virtual_file_paths': ['/b/foobar'], 'root_uid': 'bar'},
        None,
    ]
    set_root_uids(test_input, root_uid)
    assert any(item is None or item['root_uid'] == root_uid for item in test_input)
