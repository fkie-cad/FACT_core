import os

from common_helper_files import get_dir_of_file

from objects.file import FileObject
from plugins.analysis.init_systems.code.init_system import AnalysisPlugin
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest


class TestAnalysisPluginInit(AnalysisPluginTest):
    PLUGIN_NAME = "init_systems"

    @classmethod
    def setUpClass(self):
        test_init_dir = os.path.join(get_dir_of_file(__file__), 'data')
        test_files = {
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
            'initscript': 'etc/initscript'
        }

        for test_file, path in test_files.items():
            exec("self.test_file_" + test_file + " = FileObject(file_path=os.path.join(test_init_dir, path))")
            exec("self.test_file_" + test_file + ".processed_analysis['file_type'] = {'mime': 'text/plain'}")
            exec("self.test_file_" + test_file + ".root_uid = self.test_file_" + test_file + ".uid")
            exec("self.test_file_" + test_file + ".virtual_file_path = {self.test_file_" + test_file + ".get_root_uid(): [\"" + path + "\"]}")

        self.test_file_not_text = FileObject(file_path="{}etc/systemd/system/foobar".format(test_init_dir))
        self.test_file_not_text.processed_analysis['file_type'] = {'mime': 'application/zip'}

    @classmethod
    def tearDownClass(self):
        super(TestAnalysisPluginInit, self).tearDownClass()

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def tearDown(self):
        super().tearDown()

    def test_get_systemd_config(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_systemd)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertIn('/usr/sbin/foobar -n', result['ExecStart'], "record not found")
        self.assertNotIn('[Unit]', result['ExecStart'], "[Unit] should not be listed")
        self.assertNotIn("Description=Foo Bar Service", result['description'], "record not sanitized")
        self.assertEqual(['"Foo Bar Service"'], result['description'], "description missing")
        self.assertEqual(['SystemD'], result['init_type'], "init type missing")
        self.assertEqual(['SystemD'], result['summary'], "record not found in summary")

    def test_get_rc_config(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_rclocal)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual("/usr/bin/foo              # ein Programm\n/usr/local/bin/bar.sh     # ein Shellskript\n/etc/init.d/foobar start  # ein Dienst\nexit 0", result['script'], "record not found")
        self.assertNotIn("#!/bin/sh -e", result['script'], "Comments should not be listed")
        self.assertEqual(['rc'], result['init_type'], "init type missing")
        self.assertEqual(['rc'], result['summary'], "init type missing")

    def test_get_inittab_config(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_inittab)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertIn('/etc/init.d/rcS', result['inittab'], "record not found")
        self.assertIn('/sbin/getty -L 9600 ttyS0 vt320', result['inittab'], "record not found")
        self.assertEqual(['inittab'], result['init_type'], "init type missing")
        self.assertEqual(['inittab'], result['summary'], "record not found in summary")

    def test_get_initscript_config(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_initscript)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(['initscript'], result['init_type'], "init type missing")
        self.assertEqual(['initscript'], result['summary'], "record not found in summary")

    def test_get_upstart_config(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_upstart)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual('    echo "[`date`] baz starting..." >> /var/log/baz.log', result['pre-start'], "record not found")
        self.assertIn('/bin/baz.sh -runonce \\\n-silent', result['exec'], "record not found")
        self.assertNotIn('script', result['script'], "script should not be listed")
        self.assertEqual(['"Simple Baz application"'], result['description'], "description missing")
        self.assertEqual(['UpStart'], result['init_type'], "init type missing")
        self.assertEqual(['UpStart'], result['summary'], "description missing")

    def test_get_runit_config(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_runit)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual('sv -w7 check postgresql\nexec 2>&1 myprocess \\\nlast line', result['script'], "record not found")
        self.assertIn('exec 2>&1 myprocess \\\nlast line', result['script'], "record not found")
        self.assertNotIn('#!/bin/sh -e', result['script'], "should not be listed")
        self.assertEqual(['RunIt'], result['init_type'], "init type missing")
        self.assertEqual(['RunIt'], result['summary'], "description missing")

        processed_file2 = self.analysis_plugin.process_object(self.test_file_runit_symlink)
        result2 = processed_file2.processed_analysis[self.PLUGIN_NAME]
        self.assertIn('exec chpst -u foo /opt/example/foo-service.sh', result2['script'], "record not found")
        self.assertEqual(['RunIt'], result['init_type'], "init type missing")
        self.assertEqual(['RunIt'], result2['summary'], "description missing")

        processed_file3 = self.analysis_plugin.process_object(self.test_file_runit_origin)
        result3 = processed_file3.processed_analysis[self.PLUGIN_NAME]
        self.assertIn('exec chpst -u foo /opt/example/foo-service.sh', result3['script'], "record not found")
        self.assertEqual(['RunIt'], result['init_type'], "init type missing")
        self.assertEqual(['RunIt'], result3['summary'], "description missing")

    def test_get_sysvinit_config(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_initd)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual(['"Example initscript"'], result['description'], "description missing")
        self.assertIn('if [ true != "$INIT_D_SCRIPT_SOURCED" ] ; then\n    set "$0" "$@"; INIT_D_SCRIPT_SOURCED=true . /lib/init/init-d-script\nfi', result['script'], "record not found")
        self.assertEqual(['SysVInit'], result['init_type'], "init type missing")
        self.assertEqual(['SysVInit'], result['summary'], "description missing")

    def test_get_not_text_file(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_not_text)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual([], result['summary'], "should be empty summary")

    def test_readme_file(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_README)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertEqual([], result['summary'], "should be empty summary")

    def test_only_comments_file(self):
        processed_file = self.analysis_plugin.process_object(self.test_file_only_comments)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]

        self.assertDictEqual({}, result, "should be empty for comments only in file")

    def test_add_quotes(self):
        unquoted = ['test', '2']

        self.assertEqual(['"test"', '"2"'], self.analysis_plugin._add_quotes(unquoted), "strings should be in double quotes")
