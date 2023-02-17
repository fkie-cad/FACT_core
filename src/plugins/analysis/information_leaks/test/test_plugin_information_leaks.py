from pathlib import Path

import pytest

from test.common_helper import MockFileObject  # pylint: disable=wrong-import-order

from ..code.information_leaks import AnalysisPlugin, _check_file_path, _check_for_directories, _check_for_files

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginInformationLeaks:
    def test_find_path(self, analysis_plugin):
        fo = MockFileObject()
        fo.binary = (TEST_DATA_DIR / 'path_test_file').read_bytes()
        fo.processed_analysis[analysis_plugin.NAME] = {}
        fo.processed_analysis['file_type'] = {'mime': 'application/x-executable'}
        fo.virtual_file_path = {}
        analysis_plugin.process_object(fo)

        assert 'user_paths' in fo.processed_analysis[analysis_plugin.NAME]
        assert fo.processed_analysis[analysis_plugin.NAME]['user_paths'] == [
            '/home/multiple/file.a',
            '/home/multiple/file.b',
            '/home/user/test/urandom',
            '/home/user/urandom',
        ]

        assert 'www_path' in fo.processed_analysis[analysis_plugin.NAME]
        assert fo.processed_analysis[analysis_plugin.NAME]['www_path'] == ['/var/www/tmp/me_']

        assert 'root_path' in fo.processed_analysis[analysis_plugin.NAME]
        assert fo.processed_analysis[analysis_plugin.NAME]['root_path'] == ['/root/user_name/this_directory']

        assert 'summary' in fo.processed_analysis[analysis_plugin.NAME]
        assert sorted(fo.processed_analysis[analysis_plugin.NAME]['summary']) == ['root_path', 'user_paths', 'www_path']

    def test_find_artifacts(self, analysis_plugin):
        fo = MockFileObject()
        fo.processed_analysis['file_type'] = {'mime': 'text/plain'}
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
        expected_result = sorted(
            [
                'git_config',
                'pytest_cache_directory',
                'vscode_settings',
                'keil_uvision_config',
                'zsh_history',
                'any_history',
            ]
        )
        assert 'summary' in fo.processed_analysis[analysis_plugin.NAME]
        assert fo.processed_analysis[analysis_plugin.NAME]['summary'] == expected_result


def test_check_file_path():
    # if multiple rules match, only the first should appear in the result
    svn_path = '/home/user/project/.svn/entries'
    assert _check_for_files(svn_path) and _check_for_directories(svn_path), 'both rules should match'
    assert _check_file_path(svn_path) == {'svn_entries': ['/home/user/project/.svn/entries']}
