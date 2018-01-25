import gc
import unittest

from unpacker.helper.carving import CarvedArea


class TestCarvedArea(unittest.TestCase):

    def tearDown(self):
        gc.collect()

    def test_carved_complete_area(self):
        area_size = 100
        carved_and_expected = [{'carved': (0, area_size), 'expected': []},
                               {'carved': (-1, area_size + 1), 'expected': []},
                               {'carved': (-1, area_size), 'expected': []},
                               {'carved': (0, area_size + 1), 'expected': []}]
        self.caring_test(area_size, carved_and_expected)

    def test_carved_borders(self):
        area_size = 100
        carved_and_expected = [{'carved': (0, area_size - 1), 'expected': [(100, 100)]},
                               {'carved': (1, area_size), 'expected': [(0, 0)]},
                               {'carved': (-1, area_size - 1), 'expected': [(100, 100)]},
                               {'carved': (1, area_size + 1), 'expected': [(0, 0)]}]
        self.caring_test(area_size, carved_and_expected)

    def test_carved_in_between(self):
        area_size = 100
        carved_and_expected = [{'carved': (50, 60), 'expected': [(0, 49), (61, 100)]}]
        self.caring_test(area_size, carved_and_expected)

    def test_bug(self):
        area_size = 8258048
        carved_area = CarvedArea(area_size)

        carved_area.carved((0, 512))

        carved_area.carved((15440, 15504))
        carved_area.carved((15504, 48257))

        carved_area.carved((131584, 132096))
        carved_area.carved((132096, 1066830))

        carved_area.carved((1180160, 8258048))

        expected = [(513, 15439), (48258, 131583), (1066831, 1180159)]
        self.assertEqual(len(expected), len(carved_area.non_carved_areas))

        for area in expected:
            self.assertIn(area, carved_area.non_carved_areas)

    def caring_test(self, area_size, carved_and_expected):
        for test_data in carved_and_expected:
            carved_area = CarvedArea(area_size)
            carved_area.carved(test_data['carved'])

            self.assertEqual(test_data['expected'], carved_area.non_carved_areas, test_data)
