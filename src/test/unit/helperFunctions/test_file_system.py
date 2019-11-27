import os
import unittest

from helperFunctions.fileSystem import (
    _get_relative_path, file_is_empty, get_absolute_path, get_object_path_excluding_fact_dirs, get_parent_dir,
    get_src_dir, get_template_dir
)
from test.common_helper import get_test_data_dir


class TestFileSystemHelpers(unittest.TestCase):

    def setUp(self):
        self.current_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self.current_cwd)

    def test_get_parent_dir(self):
        self.assertEqual(get_parent_dir('/foo/bar/test'), '/foo/bar', 'parent directory')

    def check_correct_src_dir(self, working_directory):
        real_src_dir = get_src_dir()
        os.chdir(working_directory)
        self.assertTrue(os.path.exists('{}/helperFunctions/fileSystem.py'.format(real_src_dir)), 'fileSystem.py found in correct place')
        self.assertEqual(get_src_dir(), real_src_dir, 'same source dir before and after chdir')

    def test_get_src_dir_cwd(self):
        self.check_correct_src_dir(os.getcwd())

    def test_get_src_dir_root(self):
        self.check_correct_src_dir('/')

    def test_get_template_dir(self):
        template_dir = get_template_dir()
        self.assertTrue(os.path.isdir(template_dir), 'template dir not found')
        file_suffixes_in_template_dir = [os.path.basename(f).split('.')[-1] for f in os.listdir(template_dir)]
        self.assertTrue('html' in file_suffixes_in_template_dir)

    def test_get_absolute_path(self):
        abs_path = '/foo/bar'
        self.assertEqual(get_absolute_path(abs_path), '/foo/bar', 'absolute path of absolute path not correct')
        rel_path = 'foo/bar'
        self.assertEqual(get_absolute_path(rel_path, base_dir='/the'), '/the/foo/bar', 'absolute path of relative path not correct')

    def test_get_chroot_path(self):
        a = _get_relative_path('/foo/bar/com', '/foo/')
        self.assertEqual(a, '/bar/com', 'simple case with /')
        b = _get_relative_path('/foo/bar/com', '/foo')
        self.assertEqual(b, '/bar/com', 'simple case without /')
        c = _get_relative_path('/foo/bar/com', '/bar')
        self.assertEqual(c, '/foo/bar/com', 'none matching root')

    def test_get_chroot_excluding_extracted_prefix_dir(self):
        d = get_object_path_excluding_fact_dirs('/foo/fact_extracted/bar/com', '/foo')
        self.assertEqual(d, '/bar/com', 'including extracted')

    def test_file_is_zero(self):
        self.assertTrue(file_is_empty('{}/zero_byte'.format(get_test_data_dir())), 'file is empty but stated differently')
        self.assertFalse(file_is_empty('{}/get_files_test/testfile1'.format(get_test_data_dir())), 'file not empty but stated differently')
        self.assertFalse(file_is_empty(os.path.join(get_test_data_dir(), 'broken_link')), 'Broken link is not empty')

    def test_file_is_zero_broken_link(self):
        self.assertFalse(file_is_empty(os.path.join(get_test_data_dir(), 'broken_link')), 'Broken link is not empty')
