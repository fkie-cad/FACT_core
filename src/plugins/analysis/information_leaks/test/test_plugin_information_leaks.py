from io import FileIO
from pathlib import Path

import pytest

from ..code.information_leaks import (
    URL_REGEXES,
    AnalysisPlugin,
    _check_file_path,
    _check_for_directories,
    _check_for_files,
    _find_regex,
)

TEST_DATA_DIR = Path(__file__).parent / 'data'


class MockFile:
    @staticmethod
    def read():
        return b''


class MockTypeResult:
    def __init__(self, mime: str):
        self.mime = mime


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginInformationLeaks:
    def test_find_path(self, analysis_plugin):
        result = analysis_plugin.analyze(
            file_handle=FileIO(TEST_DATA_DIR / 'path_test_file'),
            virtual_file_path={},
            analyses={'file_type': MockTypeResult('application/x-executable')},
        )
        summary = analysis_plugin.summarize(result)

        result_dict = result.model_dump()
        assert result_dict['path_artifacts'] != []
        assert result_dict['url_artifacts'] == []
        assert sorted(result_dict['path_artifacts'], key=lambda d: (d['name'], d['path'])) == [
            {'name': 'root_path', 'path': '/root/user_name/this_directory'},
            {'name': 'user_paths', 'path': '/home/multiple/file.a'},
            {'name': 'user_paths', 'path': '/home/multiple/file.b'},
            {'name': 'user_paths', 'path': '/home/user/test/urandom'},
            {'name': 'user_paths', 'path': '/home/user/urandom'},
            {'name': 'www_path', 'path': '/var/www/tmp/me_'},
        ]

        assert sorted(summary) == ['root_path', 'user_paths', 'www_path']

    def test_find_artifacts(self, analysis_plugin):
        virtual_file_path = {
            'some_parent_uid': [
                '/home/user/project/.git/config',
                '/home/user/some_path/.pytest_cache/some_file',
                '/root/some_directory/some_more/.config/Code/User/settings.json',
                '/some_home/some_user/urandom/42/some_file.uvprojx',
                '/this_home/this_dict/.zsh_history',
                '/this_home/this_dict/.random_ambiguous_history',
                'home',
                '',
                'h654qf"§$%74672',
                'vuwreivh54r234/',
                '/vr4242fdsg4%%$',
            ]
        }
        result = analysis_plugin.analyze(
            file_handle=MockFile(),
            virtual_file_path=virtual_file_path,
            analyses={'file_type': MockTypeResult('text/plain')},
        )
        summary = analysis_plugin.summarize(result)
        expected_result = [
            'any_history',
            'git_config',
            'keil_uvision_config',
            'pytest_cache_directory',
            'vscode_settings',
            'zsh_history',
        ]
        assert sorted(summary) == expected_result


def test_check_file_path():
    # if multiple rules match, only the first should appear in the result
    svn_path = '/home/user/project/.svn/entries'
    assert _check_for_files(svn_path) and _check_for_directories(svn_path), 'both rules should match'  # noqa: PT018
    assert _check_file_path(svn_path) == {'svn_entries': ['/home/user/project/.svn/entries']}


def test_find_creds_in_urls():
    content = b'\0\0http://username:password@some.address.org/foo/bar\0\0"ftp://user:passwd@example.com"\0\0'
    result = _find_regex(content, URL_REGEXES)
    assert result['credentials_in_url'] == [
        'ftp://user:passwd@example.com',
        'http://username:password@some.address.org/foo/bar',
    ]
