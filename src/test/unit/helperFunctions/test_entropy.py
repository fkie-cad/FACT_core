import unittest
from time import sleep
from helperFunctions.entropy import generate_random_data


class TestHelperFunctionsEntropy(unittest.TestCase):

    def test_generate_random_bytes(self):
        random_bytes_one = generate_random_data(size=4, seed=1)
        self.assertIsInstance(random_bytes_one, bytes, "wrong type")
        self.assertEqual(len(random_bytes_one), 4, "wrong length")
        self.assertEqual(random_bytes_one, b'\xf5\xb1e"', "seed not working")
        # test time based random seeds
        random_data_a = generate_random_data()
        sleep(1)
        random_data_b = generate_random_data()
        self.assertNotEqual(random_data_a, random_data_b, "random initial seed not working")


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
