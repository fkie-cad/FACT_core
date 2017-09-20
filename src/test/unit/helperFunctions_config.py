'''
Created on 20.10.2015

@author: weidenba
'''
import unittest
from unittest.mock import Mock
import os
import helperFunctions
from helperFunctions.fileSystem import get_test_data_dir


class Test_helpferFunctions_Config(unittest.TestCase):

    def test_get_config_dir(self):
        from helperFunctions.config import get_config_dir
        self.assertTrue(os.path.exists("{}/main.cfg".format(get_config_dir())), "main config file not found")

    def test_load_config(self):
        helperFunctions.config.get_config_dir = Mock(return_value="{}/helperFunctions".format(get_test_data_dir()))
        test_config = helperFunctions.config.load_config("test.cfg")
        self.assertEqual(test_config["test"]['test'], "test_config", "config not correct")


if __name__ == "__main__":
    unittest.main()
