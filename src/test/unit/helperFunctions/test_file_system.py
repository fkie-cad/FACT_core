# pylint: disable=redefined-outer-name,unused-argument

import os
from pathlib import Path

import pytest

from helperFunctions.fileSystem import (
    file_is_empty,
    get_config_dir,
    get_relative_object_path,
    get_src_dir,
    get_template_dir,
)
from test.common_helper import get_test_data_dir

TEST_DATA_DIR = Path(get_test_data_dir())


@pytest.fixture()
def restore_cwd():
    current_cwd = os.getcwd()
    yield
    os.chdir(current_cwd)


@pytest.mark.parametrize('working_directory', [os.getcwd(), '/'])
def test_get_src_dir_cwd(restore_cwd, working_directory):
    real_src_dir = get_src_dir()
    os.chdir(working_directory)
    assert os.path.exists(f'{real_src_dir}/helperFunctions/fileSystem.py'), 'fileSystem.py found in correct place'
    assert get_src_dir() == real_src_dir, 'same source dir before and after chdir'


def test_get_template_dir():
    template_dir = get_template_dir()
    assert template_dir.is_dir(), 'template dir not found'
    file_suffixes_in_template_dir = [f.suffix for f in template_dir.iterdir()]
    assert '.html' in file_suffixes_in_template_dir


@pytest.mark.parametrize(
    'base, offset, result, message',
    [
        (Path('/foo/bar/com'), Path('/foo/'), '/bar/com', 'simple case with /'),
        (Path('/foo/bar/com'), Path('/foo'), '/bar/com', 'simple case without /'),
        (Path('/foo/bar/com'), Path('/bar'), '/foo/bar/com', 'non-matching root'),
        (Path('/foo/fact_extracted/bar/com'), Path('/foo'), '/bar/com', 'including extracted'),
    ],
)
def test_get_relative_object_path(base, offset, result, message):
    assert get_relative_object_path(base, offset) == result, message


def test_file_is_zero():
    assert file_is_empty(TEST_DATA_DIR / 'zero_byte'), 'file is empty but stated differently'
    assert not file_is_empty(TEST_DATA_DIR / 'get_files_test' / 'testfile1'), 'file not empty but stated differently'


def test_file_is_zero_broken_link():
    assert not file_is_empty(TEST_DATA_DIR / 'broken_link'), 'Broken link is not empty'


def test_get_config_dir():
    assert os.path.exists(f'{get_config_dir()}/main.cfg'), 'main config file not found'
