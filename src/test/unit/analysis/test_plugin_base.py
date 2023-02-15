# pylint: disable=protected-access,redefined-outer-name,unused-argument,no-self-use

from pathlib import Path

import pytest

from analysis.PluginBase import AnalysisBasePlugin, PluginInitException
from helperFunctions.fileSystem import get_src_dir
from objects.file import FileObject
from plugins.analysis.dummy.code.dummy import AnalysisPlugin as DummyPlugin

PLUGIN_PATH = Path(get_src_dir()) / 'plugins' / 'analysis'


@pytest.mark.cfg_defaults(
    {
        'dummy_plugin_for_testing_only': {
            'threads': '2',
        },
        'expert-settings': {
            'block-delay': '0.1',
        },
    }
)
@pytest.mark.AnalysisPluginTestConfig(
    plugin_class=DummyPlugin,
    start_processes=True,
)
class TestPluginBaseCore:
    def test_object_processing_no_children(self, analysis_plugin):
        root_object = FileObject(binary=b'root_file')
        analysis_plugin.in_queue.put(root_object)
        processed_object = analysis_plugin.out_queue.get()
        assert processed_object.uid == root_object.uid, 'uid changed'
        assert 'dummy_plugin_for_testing_only' in processed_object.processed_analysis, 'object not processed'
        assert (
            processed_object.processed_analysis['dummy_plugin_for_testing_only']['plugin_version'] == '0.0'
        ), 'plugin version missing in results'
        assert (
            processed_object.processed_analysis['dummy_plugin_for_testing_only']['analysis_date'] > 1
        ), 'analysis date missing in results'

    def test_object_processing_one_child(self, analysis_plugin):
        root_object = FileObject(binary=b'root_file')
        child_object = FileObject(binary=b'first_child_object')
        root_object.add_included_file(child_object)
        analysis_plugin.in_queue.put(root_object)
        processed_object = analysis_plugin.out_queue.get()
        assert processed_object.uid == root_object.uid, 'uid changed'
        assert child_object.uid in root_object.files_included, 'child object not in processed file'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=DummyPlugin)
class TestPluginBaseAddJob:
    def test_analysis_depth_not_reached_yet(self, analysis_plugin):
        fo = FileObject(binary=b'test', scheduled_analysis=[])

        fo.depth = 1
        analysis_plugin.RECURSIVE = False
        assert not analysis_plugin._analysis_depth_not_reached_yet(fo), 'positive but not root object'

        fo.depth = 0
        analysis_plugin.RECURSIVE = False
        assert analysis_plugin._analysis_depth_not_reached_yet(fo)

        fo.depth = 1
        analysis_plugin.RECURSIVE = True
        assert analysis_plugin._analysis_depth_not_reached_yet(fo)

        fo.depth = 0
        analysis_plugin.RECURSIVE = True
        assert analysis_plugin._analysis_depth_not_reached_yet(fo)

    @pytest.mark.AnalysisPluginTestConfig(start_processes=True)
    def test__add_job__recursive_is_set(self, analysis_plugin):
        fo = FileObject(binary=b'test', scheduled_analysis=[])
        fo.depth = 1
        analysis_plugin.recursive = False
        analysis_plugin.add_job(fo)
        out_fo = analysis_plugin.out_queue.get(timeout=5)
        assert isinstance(out_fo, FileObject), 'not added to out_queue'
        analysis_plugin.recursive = True
        assert analysis_plugin._analysis_depth_not_reached_yet(fo), 'not positive but recursive'


class TestPluginBaseOffline:
    def test_get_view_file_path(self):
        code_path = PLUGIN_PATH / 'file_type' / 'code' / 'file_type.py'
        expected_view_path = PLUGIN_PATH / 'file_type' / 'view' / 'file_type.html'

        assert AnalysisBasePlugin._get_view_file_path(str(code_path)) == expected_view_path

        without_view = PLUGIN_PATH / 'dummy' / 'code' / 'dummy.py'
        assert AnalysisBasePlugin._get_view_file_path(str(without_view)) is None


class TestPluginNotRunning:
    def multithread_config_test(self, multithread_flag, threads_wanted):
        self.p_base = DummyPlugin(no_multithread=multithread_flag)
        assert self.p_base.thread_count == int(threads_wanted), 'number of threads not correct'
        self.p_base.shutdown()

    @pytest.mark.cfg_defaults(
        {
            'dummy_plugin_for_testing_only': {
                'threads': '4',
            }
        }
    )
    def test_no_multithread(self):
        self.multithread_config_test(True, '1')

    @pytest.mark.cfg_defaults(
        {
            'dummy_plugin_for_testing_only': {
                'threads': '2',
            }
        }
    )
    def test_normal_multithread(self):
        self.multithread_config_test(False, '2')

    def test_init_result_dict(self):
        self.p_base = DummyPlugin()
        resultdict = self.p_base.init_dict()
        assert 'analysis_date' in resultdict, 'analysis date missing'
        assert resultdict['plugin_version'] == '0.0', 'plugin version field not correct'
        self.p_base.shutdown()


@pytest.mark.AnalysisPluginTestConfig(plugin_class=DummyPlugin)
def test_timeout(analysis_plugin, monkeypatch):
    analysis_plugin.TIMEOUT = 0
    analysis_plugin.start()

    fo_in = FileObject(binary=b'test', scheduled_analysis=[])
    analysis_plugin.add_job(fo_in)
    fo_out = analysis_plugin.out_queue.get(timeout=5)

    assert 'summary' not in fo_out.processed_analysis['dummy_plugin_for_testing_only']


def test_attribute_check():
    with pytest.raises(PluginInitException):
        AnalysisBasePlugin()
