import os
from copy import deepcopy

import pytest
from common_helper_files import get_dir_of_file

from objects.file import FileObject
from plugins.analysis.init_systems.code.init_system import AnalysisPlugin

_test_init_dir = os.path.join(get_dir_of_file(__file__), 'data')  # noqa: PTH118


def _get_fo(path):
    fo = FileObject(file_path=os.path.join(_test_init_dir, path))  # noqa: PTH118
    fo.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}
    fo.root_uid = fo.uid
    fo.virtual_file_path = {'parent_uid': [path]}
    return fo


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginInit:
    test_file_not_text = FileObject(file_path=f'{_test_init_dir}/etc/systemd/system/foobar')
    test_file_not_text.processed_analysis['file_type'] = {'result': {'mime': 'application/zip'}}  # noqa: RUF012

    test_files = {  # noqa: RUF012
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
    test_fos = {f'test_file_{test_file}': _get_fo(path) for test_file, path in test_files.items()}  # noqa: RUF012

    def test_root_uid_is_none(self, analysis_plugin):
        fo = deepcopy(self.test_fos['test_file_initd'])
        fo.root_uid = None
        fo.parent_firmware_uids = set(fo.virtual_file_path)
        processed_file = analysis_plugin.process_object(fo)
        # missing fo.root_uid should not break the analysis
        assert processed_file.processed_analysis[analysis_plugin.NAME]['summary'] != []

    def test_get_systemd_config(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_systemd'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert '/usr/sbin/foobar -n' in result['ExecStart'], 'record not found'
        assert '[Unit]' not in result['ExecStart'], '[Unit] should not be listed'
        assert 'Description=Foo Bar Service' not in result['description'], 'record not sanitized'
        assert ['"Foo Bar Service"'] == result['description'], 'description missing'
        assert ['SystemD'] == result['init_type'], 'init type missing'
        assert ['SystemD'] == result['summary'], 'record not found in summary'

    def test_get_rc_config(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_rclocal'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert (
            '/usr/bin/foo              # ein Programm\n/usr/local/bin/bar.sh     # ein Shellskript\n/etc/init.d/foobar start  # ein Dienst\nexit 0'  # noqa: SIM300, E501
            == result['script']
        ), 'record not found'
        assert '#!/bin/sh -e' not in result['script'], 'Comments should not be listed'
        assert ['rc'] == result['init_type'], 'init type missing'
        assert ['rc'] == result['summary'], 'init type missing'

    def test_get_inittab_config(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_inittab'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert '/etc/init.d/rcS' in result['inittab'], 'record not found'
        assert '/sbin/getty -L 9600 ttyS0 vt320' in result['inittab'], 'record not found'
        assert ['inittab'] == result['init_type'], 'init type missing'
        assert ['inittab'] == result['summary'], 'record not found in summary'

    def test_get_initscript_config(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_initscript'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert ['initscript'] == result['init_type'], 'init type missing'
        assert ['initscript'] == result['summary'], 'record not found in summary'

    def test_get_upstart_config(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_upstart'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert result['pre-start'] == '    echo "[`date`] baz starting..." >> /var/log/baz.log', 'record not found'
        assert '/bin/baz.sh -runonce \\\n-silent' in result['exec'], 'record not found'
        assert 'script' not in result['script'], 'script should not be listed'
        assert ['"Simple Baz application"'] == result['description'], 'description missing'
        assert ['UpStart'] == result['init_type'], 'init type missing'
        assert ['UpStart'] == result['summary'], 'description missing'

    def test_get_runit_config(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_runit'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert result['script'] == 'sv -w7 check postgresql\nexec 2>&1 myprocess \\\nlast line', 'record not found'
        assert 'exec 2>&1 myprocess \\\nlast line' in result['script'], 'record not found'
        assert '#!/bin/sh -e' not in result['script'], 'should not be listed'
        assert ['RunIt'] == result['init_type'], 'init type missing'
        assert ['RunIt'] == result['summary'], 'description missing'

        processed_file2 = analysis_plugin.process_object(self.test_fos['test_file_runit_symlink'])
        result2 = processed_file2.processed_analysis[analysis_plugin.NAME]
        assert 'exec chpst -u foo /opt/example/foo-service.sh' in result2['script'], 'record not found'
        assert ['RunIt'] == result['init_type'], 'init type missing'
        assert ['RunIt'] == result2['summary'], 'description missing'

        processed_file3 = analysis_plugin.process_object(self.test_fos['test_file_runit_origin'])
        result3 = processed_file3.processed_analysis[analysis_plugin.NAME]
        assert 'exec chpst -u foo /opt/example/foo-service.sh' in result3['script'], 'record not found'
        assert ['RunIt'] == result['init_type'], 'init type missing'
        assert ['RunIt'] == result3['summary'], 'description missing'

    def test_get_sysvinit_config(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_initd'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert ['"Example initscript"'] == result['description'], 'description missing'
        assert (
            'if [ true != "$INIT_D_SCRIPT_SOURCED" ] ; then\n    set "$0" "$@"; INIT_D_SCRIPT_SOURCED=true . /lib/init/init-d-script\nfi'  # noqa: E501
            in result['script']
        ), 'record not found'
        assert ['SysVInit'] == result['init_type'], 'init type missing'
        assert ['SysVInit'] == result['summary'], 'description missing'

    def test_get_not_text_file(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_file_not_text)
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert [] == result['summary'], 'should be empty summary'

    def test_readme_file(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_README'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert [] == result['summary'], 'should be empty summary'

    def test_only_comments_file(self, analysis_plugin):
        processed_file = analysis_plugin.process_object(self.test_fos['test_file_only_comments'])
        result = processed_file.processed_analysis[analysis_plugin.NAME]

        assert {} == result, 'should be empty for comments only in file'

    def test_add_quotes(self, analysis_plugin):
        unquoted = ['test', '2']

        assert ['"test"', '"2"'] == analysis_plugin._add_quotes(unquoted), 'strings should be in double quotes'
