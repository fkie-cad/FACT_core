'''
Created on Nov 17, 2015

@author: weidenba
'''
import unittest

from helperFunctions.dependency import schedule_dependencies, get_unmatched_dependencies


class MockFileObject:
    def __init__(self, processed_analysis_list):
        self.processed_analysis = processed_analysis_list


class TestHelperFunctionsDependencySchedule(unittest.TestCase):

    def schedule_test(self, schedule_list, dependency_list, myself, out_list):
        new_schedule = schedule_dependencies(schedule_list, dependency_list, myself)
        self.assertEqual(new_schedule, out_list, 'schedule not correct')

    def test_schedule_simple_case(self):
        self.schedule_test(['a', 'b'], ['b'], 'c', ['c', 'a', 'b'])

    def test_schedule_not_in_list(self):
        self.schedule_test([], ['a'], 'b', ['b', 'a'])

    def test_schedule_multiple_in_not_in_list(self):
        self.schedule_test(['a', 'b'], ['b', 'c', 'd', 'a'], 'e', ['e', 'a', 'b', 'c', 'd'])


class TestHelperFunctionsDependencyMatch(unittest.TestCase):

    def unmatched_dependency_test(self, processed_list, dependencies, out_list):
        unmatched_dependencies = get_unmatched_dependencies(processed_list, dependencies)
        self.assertEqual(unmatched_dependencies, out_list, 'unmatched dependency list not correct')

    def test_unmatched_dependency_not_solved(self):
        self.unmatched_dependency_test([MockFileObject([])], ['a'], ['a'])

    def test_unmatched_dependency_solved(self):
        self.unmatched_dependency_test([MockFileObject(['a'])], ['a'], [])

    def test_unmatched_dependencies_multiple_solved_unsolved(self):
        self.unmatched_dependency_test([MockFileObject(['a', 'b'])], ['a', 'b', 'c', 'd'], ['c', 'd'])

    def test_unmatched_dependencies_multiple_file_objects(self):
        self.unmatched_dependency_test([MockFileObject(['b']), MockFileObject(['a'])], ['a', 'b'], ['a', 'b'])


if __name__ == "__main__":
    unittest.main()
