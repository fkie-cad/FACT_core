from pathlib import Path

import pytest

from test.common_helper import MockFileObject

from ..code.information_leaks import AnalysisPlugin, _check_file_path, _check_for_directories, _check_for_files

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginInformationLeaks:
    def test_find_path(self, analysis_plugin):
        fo = MockFileObject()
        fo.binary = (TEST_DATA_DIR / 'path_test_file').read_bytes()
        fo.processed_analysis[analysis_plugin.NAME] = {}
        fo.processed_analysis['file_type'] = {'result': {'mime': 'application/x-executable'}}
        fo.virtual_file_path = {}
        analysis_plugin.process_object(fo)

        result = fo.processed_analysis[analysis_plugin.NAME]
        assert 'user_paths' in result
        assert result['user_paths'] == [  # type: ignore[comparison-overlap]
            '/home/multiple/file.a',
            '/home/multiple/file.b',
            '/home/user/test/urandom',
            '/home/user/urandom',
        ]

        assert 'www_path' in result
        assert result['www_path'] == ['/var/www/tmp/me_']  # type: ignore[comparison-overlap]

        assert 'root_path' in result
        assert result['root_path'] == ['/root/user_name/this_directory']  # type: ignore[comparison-overlap]

        assert 'summary' in result
        assert sorted(result['summary']) == ['root_path', 'user_paths', 'www_path']

    def test_find_artifacts(self, analysis_plugin):
        fo = MockFileObject()
        fo.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}
        fo.virtual_file_path = {
            1: [
                'some_uid|/home/user/project/.git/config',
                'some_uid|/home/user/some_path/.pytest_cache/some_file',
                'some_uid|/root/some_directory/some_more/.config/Code/User/settings.json',
                'some_uid|/some_home/some_user/urandom/42/some_file.uvprojx',
                'some_uid|some_more_uid|/this_home/this_dict/.zsh_history',
                'some_uid|some_more_uid|/this_home/this_dict/.random_ambiguous_history',
                'some_uid|home',
                'some_uid|',
                'some_uid|h654qf"§$%74672',
                'some_uid|vuwreivh54r234/',
                'some_uid|/vr4242fdsg4%%$',
            ]
        }
        analysis_plugin.process_object(fo)
        result = fo.processed_analysis[analysis_plugin.NAME]
        assert 'summary' in result
        assert result['summary'] == [  # type: ignore[comparison-overlap]
            'any_history',
            'git_config',
            'keil_uvision_config',
            'pytest_cache_directory',
            'vscode_settings',
            'zsh_history',
        ]


def test_check_file_path():
    # if multiple rules match, only the first should appear in the result
    svn_path = '/home/user/project/.svn/entries'
    assert _check_for_files(svn_path) and _check_for_directories(svn_path), 'both rules should match'  # noqa: PT018
    assert _check_file_path(svn_path) == {'svn_entries': ['/home/user/project/.svn/entries']}
