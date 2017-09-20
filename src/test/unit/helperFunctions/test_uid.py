import unittest
from helperFunctions.uid import create_uid, is_uid, is_list_of_uids


class Test_helperFunctionsUID(unittest.TestCase):

    test_uid = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08_4"

    def test_create_uid(self):
        result = create_uid("test")
        self.assertEqual(result, self.test_uid, "uid not correct")

    def test_is_uid(self):
        self.assertFalse(is_uid(None))
        self.assertFalse(is_uid("blah"))
        self.assertTrue(is_uid(self.test_uid))
        self.assertFalse(is_uid(self.test_uid + "foobar"))

    def test_is_uid_list(self):
        self.assertFalse(is_list_of_uids("blah"))
        self.assertFalse(is_list_of_uids(['foobar']))
        self.assertFalse(is_list_of_uids([]))
        self.assertTrue([self.test_uid], "uid list not recognized")

if __name__ == "__main__":
    unittest.main()
