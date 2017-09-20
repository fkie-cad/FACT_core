import unittest
from helperFunctions.sort import sort_nice_data_list_by_virtual_path


class Test_helperFunctions_sort(unittest.TestCase):

    def test_sort_fo_list_by_virtual_path(self):
        a = {"virtual_file_paths": ["/a/foobar"]}
        b = {"virtual_file_paths": ["/b/foobar"]}
        c = {"virtual_file_paths": ["/c/foobar"]}
        test_list = [c, b, a]
        self.assertEqual(sort_nice_data_list_by_virtual_path(test_list), [a, b, c], "not sorted correct")
