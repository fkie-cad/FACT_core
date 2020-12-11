import logging
import os


def get_src_dir() -> str:
    '''
    Returns the absolute path of the src directory
    '''
    return get_parent_dir(get_directory_of_current_file())


def get_template_dir() -> str:
    '''
    Returns the absolute path of the template directory
    '''
    return os.path.join(get_src_dir(), 'web_interface/templates')


def get_directory_of_current_file() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def get_parent_dir(dir_path: str) -> str:
    '''
    Returns the path to the parent directory.
    '''
    dir_path = dir_path.split('/')
    dir_path = dir_path[0:len(dir_path) - 1]
    dir_path = '/'.join(dir_path)
    return dir_path


def get_absolute_path(path: str, base_dir=os.getcwd()) -> str:
    '''
    Returns path if path is absolute
    Returns base_dir/path if path is relative
    '''
    if path[0] == '/':
        return path
    return os.path.join(base_dir, path)


def get_object_path_excluding_fact_dirs(absolute_path: str, offset_path: str) -> str:
    '''
    FACT extraction drops files into a temporary directory. These have to be offset to get the path a file has on the
    firmware filesystem.
    Additionally, some filesystem extractors create an intermediate directory 'fact_extracted' that has to be removed
    as well.
    '''
    tmp = _get_relative_path(absolute_path, offset_path)
    return _get_relative_path(tmp, '/fact_extracted')


def _get_relative_path(absolute_path: str, base_path: str) -> str:
    '''
    Returns a new root for a path
    Example:
    Input: absolute_path=/foo/bar/abc, base_path=/foo/
    Output: /bar/abc
    '''
    # TODO Should be replaced by some use of Path.relative_to
    if absolute_path[0:len(base_path)] == base_path:
        new_path = absolute_path[len(base_path):len(absolute_path)]
        if new_path[0] != '/':
            new_path = '/{}'.format(new_path)
        return new_path
    return absolute_path


def file_is_empty(file_path: str) -> bool:
    '''
    Returns True if file in file_path has 0 Bytes
    Returns False otherwise
    '''
    try:
        if os.path.getsize(str(file_path)) == 0:
            return True
    except (FileNotFoundError, PermissionError, OSError):
        return False
    except Exception as exception:
        logging.error('Unexpected Exception: {} {}'.format(type(exception), str(exception)))
    else:
        return False
