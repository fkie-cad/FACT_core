'''
Created on Nov 17, 2015

@author: weidenba
'''
import unittest

from helperFunctions.dependency import schedule_dependencys, get_unmatched_dependencys


class Test_helperFunctions_dependency_schedule(unittest.TestCase):

    def schedule_test(self, schedule_list, dependency_list, myself, out_list):
        new_schedule = schedule_dependencys(schedule_list, dependency_list, myself)
        self.assertEqual(new_schedule, out_list, "schedule not correct")

    def test_schedule_simple_case(self):
        self.schedule_test(['a', 'b'], ['b'], 'c', ['c', 'a', 'b'])

    def test_schedule_not_in_list(self):
        self.schedule_test([], ['a'], 'b', ['b', 'a'])

    def test_schedule_multiple_in_not_in_list(self):
        self.schedule_test(['a', 'b'], ['b', 'c', 'd', 'a'], 'e', ['e', 'a', 'b', 'c', 'd'])


class Test_helperFunctions_dependency_match(unittest.TestCase):

    def unmatched_dependency_test(self, processed_list, dependencys, out_list):
        unmateched_deps = get_unmatched_dependencys(processed_list, dependencys)
        self.assertEqual(unmateched_deps, out_list, 'unmatched dependency list not correct')

    def test_unmatched_dependency_not_solved(self):
        self.unmatched_dependency_test([], ['a'], ['a'])

    def test_unmatched_dependency_solved(self):
        self.unmatched_dependency_test(['a'], ['a'], [])

    def test_unmatched_depecndencys_multiple_solved_unsolved(self):
        self.unmatched_dependency_test(['a', 'b'], ['a', 'b', 'c', 'd'], ['c', 'd'])


if __name__ == "__main__":
    unittest.main()
