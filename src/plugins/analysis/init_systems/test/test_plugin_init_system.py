from io import FileIO
from pathlib import Path

import pytest

from plugins.analysis.init_systems.code.init_system import AnalysisPlugin

TEST_FILES_DIR = Path(__file__).parent / 'data'
TEST_FILES = {
    'systemd': 'etc/systemd/system/foobar',
    'inittab': 'etc/inittab',
    'rclocal': 'etc/rc.local',
    'upstart': 'etc/init/baz.conf',
    'runit': 'etc/service/lighttpd/run',
    'runit_symlink': 'etc/service/example/run',
    'runit_origin': 'etc/sv/example/run',
    'only_comments': 'etc/inittab.invalid',
    'initd': 'etc/init.d/skeleton',
    'README': 'etc/init.d/README',
    'initscript': 'etc/initscript',
}


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginInit:
    @staticmethod
    def _analyze_test_file(analysis_plugin, test_file: str):
        path = TEST_FILES[test_file]
        result = analysis_plugin.analyze(FileIO(TEST_FILES_DIR / path), {'parent_uid': [path]}, {})
        summary = analysis_plugin.summarize(result)
        return result, summary

    def test_get_systemd_config(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'systemd')

        assert result.data is not None
        assert '/usr/sbin/foobar -n' in result.data.exec_start, 'ExecStart record not found'
        assert '[Unit]' not in result.data.exec_start, '[Unit] should not be listed'
        assert 'Description=' not in result.data.description, 'record not sanitized'
        assert result.data.description == 'Foo Bar Service', 'description missing'
        assert result.init_type == 'SystemD', 'init type missing'
        assert summary == ['SystemD'], 'record not found in summary'

    def test_get_rc_config(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'rclocal')

        assert result.init_type == 'rc', 'init type missing'
        assert summary == ['rc'], 'init type missing'

    def test_get_inittab_config(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'inittab')

        assert '/etc/init.d/rcS' in result.data.sysinit, 'record not found'
        assert '/sbin/getty -L 9600 ttyS0 vt320' in result.data.respawn, 'record not found'
        assert result.init_type == 'inittab', 'init type missing'
        assert summary == ['inittab'], 'record not found in summary'

    def test_get_initscript_config(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'initscript')

        assert result.init_type == 'initscript', 'init type missing'
        assert summary == ['initscript'], 'record not found in summary'

    def test_get_upstart_config(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'upstart')

        assert result.data.pre_start == '    echo "[`date`] baz starting..." >> /var/log/baz.log', 'record not found'
        assert '/bin/baz.sh -runonce \\\n-silent' in result.data.exec, 'record not found'
        assert result.data.description == '"Simple Baz application"', 'description missing'
        assert result.init_type == 'UpStart', 'init type missing'
        assert summary == ['UpStart'], 'description missing'

    def test_get_runit_config(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'runit')

        assert result.init_type == 'RunIt', 'init type missing'
        assert summary == ['RunIt'], 'description missing'

    def test_get_runit_config2(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'runit_symlink')
        assert result.init_type == 'RunIt', 'init type missing'
        assert summary == ['RunIt'], 'description missing'

    def test_get_runit_config3(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'runit_origin')
        assert result.init_type == 'RunIt', 'init type missing'
        assert summary == ['RunIt'], 'description missing'

    def test_get_sysvinit_config(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'initd')

        assert result.data.short_description == 'Example initscript', 'short description missing'
        assert result.data.description == 'Description of the service', 'description missing'
        assert result.init_type == 'SysVInit', 'init type missing'
        assert summary == ['SysVInit'], 'description missing'

    def test_readme_file(self, analysis_plugin):
        result, summary = self._analyze_test_file(analysis_plugin, 'README')

        assert result.is_init is False
        assert summary == [], 'should be empty summary'

    def test_only_comments_file(self, analysis_plugin):
        result, _ = self._analyze_test_file(analysis_plugin, 'only_comments')

        assert result.is_init is False, 'should be empty for comments only in file'
