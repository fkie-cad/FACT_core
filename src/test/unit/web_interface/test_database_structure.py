import unittest

from web_interface.database_structure import _visualize_sub_tree, visualize_complete_tree


class TestDatabaseStructure(unittest.TestCase):
    _test_strings = [
        'node1.sub1.leaf1', 'node1.sub1.leaf2', 'node1.sub2', 'node1.sub3.leaf1', 'node2', 'node3.sub1', 'node3.sub2'
    ]
    _expected_result_lines = [
        'node1',
        '  sub1',
        '    leaf1',
        '    leaf2',
        '  sub2',
        '  sub3',
        '    leaf1',
        'node2',
        'node3',
        '  sub1',
        '  sub2'
    ]

    def test_full_result(self):
        full_result = visualize_complete_tree(self._test_strings)
        self.assertCountEqual(
            full_result['complete'].splitlines(),
            self._expected_result_lines,
            'Some nodes are not represented correctly'
        )

    def test_partial_tree(self):
        self.assertCountEqual(
            _visualize_sub_tree(self._test_strings, 'node1'),
            self._expected_result_lines[:7],
            'Some node1 items are missing'
        )
        self.assertCountEqual(
            _visualize_sub_tree(self._test_strings, 'node3'),
            self._expected_result_lines[8:],
            'Some node3 items are missing'
        )
