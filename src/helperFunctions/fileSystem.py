import logging
import os
import sys


def get_src_dir():
    '''
    Returns the absolute path of the src directory
    '''
    return get_parent_dir(get_directory_of_current_file())


def get_test_data_dir():
    '''
    Returns the absolute path of the test data directory
    '''
    return os.path.join(get_src_dir(), 'test/data')


def get_faf_bin_dir():
    '''
    Returns the absolute path of the bin directory
    '''
    return os.path.join(get_src_dir(), 'bin')


def get_template_dir():
    '''
    Returns the absolute path of the template directory
    '''
    return os.path.join(get_src_dir(), 'web_interface/templates')


def get_directory_of_current_file():
    return os.path.dirname(os.path.abspath(__file__))


def get_parent_dir(dir_path):
    dir_path = dir_path.split('/')
    dir_path = dir_path[0:len(dir_path) - 1]
    dir_path = '/'.join(dir_path)
    return dir_path


def get_absolute_path(path, base_dir=os.getcwd()):
    '''
    Returns path if path is absolute
    Returns base_dir/path if path is relative
    '''
    if path[0] == '/':
        return path
    else:
        return os.path.join(base_dir, path)


def get_chroot_path(absolute_path, base_path):
    '''
    set new root for path
    example:
    input: absolute_path=/foo/bar/abc, base_path=/foo/
    output: /bar/abc
    '''
    if absolute_path[0:len(base_path)] == base_path:
        new_path = absolute_path[len(base_path):len(absolute_path)]
        if new_path[0] != '/':
            new_path = '/{}'.format(new_path)
        return new_path
    else:
        return absolute_path


def get_chroot_path_excluding_extracted_dir(absolute_path, base_path):
    '''
    like get_chroot_path but removing 'faf_extracted' dir as well
    '''
    tmp = get_chroot_path(absolute_path, base_path)
    return get_chroot_path(tmp, '/faf_extracted')


def file_is_empty(file_path):
    '''
    Returns True if file in file_path has 0 Bytes
    Returns False otherwise
    '''
    try:
        if os.path.getsize(file_path) == 0:
            return True
    except (FileNotFoundError, PermissionError, OSError):
        return False
    except Exception as e:
        logging.error('Unexpected Exception: {} {}'.format(sys.exc_info()[0].__name__, e))
    else:
        return False
