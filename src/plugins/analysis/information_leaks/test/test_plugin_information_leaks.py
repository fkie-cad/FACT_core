from pathlib import Path

from test.common_helper import MockFileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.information_leaks import AnalysisPlugin

TEST_DATA_DIR = Path(__file__).parent / 'data'


class TestAnalysisPluginInformationLeaks(AnalysisPluginTest):

    PLUGIN_NAME = 'information_leaks'
    PLUGIN_CLASS = AnalysisPlugin

    def test_find_path(self):
        fo = MockFileObject()
        fo.binary = (TEST_DATA_DIR / 'path_test_file').read_bytes()
        fo.processed_analysis[self.PLUGIN_NAME] = {}
        fo.processed_analysis['file_type'] = {'mime': 'application/x-executable'}
        fo.virtual_file_path = {}
        self.analysis_plugin.process_object(fo)

        assert 'user_paths' in fo.processed_analysis[self.PLUGIN_NAME]
        assert fo.processed_analysis[self.PLUGIN_NAME]['user_paths'] == [
            '/home/user/test/urandom', '/home/user/urandom'
        ]

        assert 'www_path' in fo.processed_analysis[self.PLUGIN_NAME]
        assert fo.processed_analysis[self.PLUGIN_NAME]['www_path'] == ['/var/www/tmp/me_']

        assert 'root_path' in fo.processed_analysis[self.PLUGIN_NAME]
        assert fo.processed_analysis[self.PLUGIN_NAME]['root_path'] == ['/root/user_name/this_directory']

        assert 'summary' in fo.processed_analysis[self.PLUGIN_NAME]
        assert fo.processed_analysis[self.PLUGIN_NAME]['summary'] == [
            '/home/user/test/urandom', '/home/user/urandom', '/root/user_name/this_directory', '/var/www/tmp/me_'
        ]

    def test_find_artifacts(self):
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
                'some_uid|/vr4242fdsg4%%$'
            ]
        }
        self.analysis_plugin.process_object(fo)
        expected_result = sorted(
            [
                'git_config',
                'pytest_cache_directory',
                'vscode_settings',
                'keil_uvision_config',
                'zsh_history',
                'any_history'
            ]
        )
        assert 'summary' in fo.processed_analysis[self.PLUGIN_NAME]
        assert fo.processed_analysis[self.PLUGIN_NAME]['summary'] == expected_result
