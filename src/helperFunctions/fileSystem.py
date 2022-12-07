import logging
from contextlib import suppress
from pathlib import Path


def get_src_dir() -> str:
    '''
    Retrieves the absolute path of the src directory.

    :return: The (absolute) path of the src directory.
    '''
    return str(Path(__file__).parent.parent)


def get_template_dir() -> Path:
    '''
    Retrieves the absolute path of the template directory.

    :return: The (absolute) path of the template directory.
    '''
    return Path(get_src_dir()) / 'web_interface' / 'templates'


def get_relative_object_path(path: Path, offset_path: Path) -> str:
    '''
    FACT extraction unpacks files into a temporary directory. These files have to be offset to get the path relative
    to the firmware filesystem root. Additionally, some filesystem extractors create an intermediate directory
    'fact_extracted' that has to be removed.

    :param path: The absolute path of the file related to the firmware or file object.
    :param offset_path: The path of the unpacking directory (that needs to be removed from the file's path).
    :return: The relative path.
    '''
    with suppress(ValueError):
        path = path.relative_to(offset_path)
        path = path.relative_to('fact_extracted')
    return str(path) if path.is_absolute() else f'/{path}'


def file_is_empty(file_path: Path) -> bool:
    '''
    Checks if a file is empty (i.e. has a size of 0 bytes).

    :param file_path: The file to check.
    :return: True if the file is empty and False otherwise.
    '''
    try:
        if file_path.is_symlink():
            file_path = file_path.resolve()
        return file_path.lstat().st_size == 0
    except (FileNotFoundError, PermissionError, OSError):
        return False
    except Exception as exception:
        logging.error(f'Unexpected Exception: {type(exception)} {str(exception)}')


def get_config_dir():
    '''
    Returns the absolute path of the config directory
    '''
    return f'{get_src_dir()}/config'
