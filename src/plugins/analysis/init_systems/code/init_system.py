import re

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.dataConversion import make_unicode_string

FILE_IGNORES = ['README', 'README.md', 'README.txt', 'INSTALL', 'VERSION']


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This Plugin searches for Init-Scripts and lists the Services or Script-Files
    It displays a short description (if provided) or else the filename

    Credits:
    Original version by Stefan Viergutz created during Firmware Bootcamp WT16/17 at University of Bonn
    Refactored and improved by Fraunhofer FKIE
    '''
    NAME = 'init_systems'
    DESCRIPTION = 'detect and analyze auto start services'
    DEPENDENCIES = ['file_type']
    VERSION = '0.4.1'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    @staticmethod
    def _is_text_file(file_object):
        return file_object.processed_analysis['file_type']['mime'] in ['text/plain']

    @staticmethod
    def _get_file_path(file_object):
        return file_object.get_top_of_virtual_path(file_object.virtual_file_path[file_object.root_uid][0])

    def _get_systemd_config(self, file_object):
        result = dict()
        match_description = self._findall_regex(r'(?:Description=)(.*)', self.content)
        match_exec = self._findall_regex(r'(?<=ExecStart=).*', self.content)
        if match_exec:
            result['ExecStart'] = '\n'.join(match_exec)
        description = match_description if match_description else []
        description = self._add_quotes(description)
        result['description'] = description if description else [file_object.file_name]
        result['init_type'] = ['SystemD']
        result['summary'] = result['init_type']
        return result

    def _get_rc_config(self, _):
        result = dict()
        matches = self._findall_regex(r'^(?!#)(.+)', self.content)
        if matches:
            result['script'] = '\n'.join(matches)
        result['init_type'] = ['rc']
        result['summary'] = result['init_type']
        return result

    def _get_inittab_config(self, _):
        result = dict()
        matches_sysinit = self._findall_regex(r'^[^#].*(?<=sysinit:)([^#].*)', self.content)
        matches_respawn = self._findall_regex(r'^[^#].*(?<=respawn:)([^#].*)', self.content)
        all_matches = list()
        all_matches.extend(list(matches_sysinit))
        all_matches.extend(list(matches_respawn))
        if all_matches:
            result['inittab'] = '\n'.join(all_matches)
            result['init_type'] = ['inittab']
            result['summary'] = result['init_type']
        return result

    def _get_initscript_config(self, _):
        result = dict()
        matches = self._findall_regex(r'^(?!#)(.+)', self.content)
        if matches:
            result['script'] = '\n'.join(matches)
        result['init_type'] = ['initscript']
        result['summary'] = result['init_type']
        return result

    def _get_upstart_config(self, file_object):
        result = dict()
        match_description = self._findall_regex(r'^[^#].*(?<=description)\s*(.*)', self.content)
        match_exec = self._findall_regex(r'[^#]^exec\s*((?:.*\\\n)*.*)', self.content)
        match_pre_start = self._findall_regex(r'(?<=pre-start script\n)(?:(?:[\S\s]*?)[\n]*)(?=\nend script)', self.content)
        match_script = self._findall_regex(r'(?<=^script\n)(?:(?:[\S\s]*?)[\n]*)(?=\nend script)', self.content)
        result['description'] = match_description if match_description else [file_object.file_name]
        if match_exec:
            result['exec'] = '\n'.join(match_exec)
        if match_pre_start:
            result['pre-start'] = '\n'.join(match_pre_start)
        if match_script:
            result['script'] = '\n'.join(match_script)
        result['init_type'] = ['UpStart']
        result['summary'] = result['init_type']
        return result

    def _get_runit_config(self, file_object):
        # TODO description = filepath
        result = dict()
        match_exec = self._findall_regex(r'^([^#](?:.*\\\n)*.*)', self.content)
        if match_exec:
            result['script'] = '\n'.join(match_exec)
        result['description'] = [file_object.file_name]
        result['init_type'] = ['RunIt']
        result['summary'] = result['init_type']
        return result

    def _get_sysvinit_config(self, file_object):
        result = dict()
        match_desc1 = self._findall_regex(r'Short-Description:\s*(.*)', self.content)
        match_desc2 = self._findall_regex(r'DESC=\"*([^\"|\n]*)', self.content)
        matches = self._findall_regex(r'^(?!#)(.+)', self.content)
        description = match_desc1 if match_desc1 else match_desc2 if match_desc2 else []
        description_formatted = self._add_quotes(description)
        result['description'] = description_formatted if description_formatted else [file_object.file_name]
        if matches:
            result['script'] = '\n'.join(matches)
        result['init_type'] = ['rc']
        result['init_type'] = ['SysVInit']
        result['summary'] = result['init_type']
        return result

    def process_object(self, file_object):
        if self._is_text_file(file_object) and (file_object.file_name not in FILE_IGNORES):
            self.file_path = self._get_file_path(file_object)
            self.content = make_unicode_string(file_object.binary)
            if '/inittab' in self.file_path:
                file_object.processed_analysis[self.NAME] = self._get_inittab_config(file_object)
            if 'systemd/system/' in self.file_path:
                file_object.processed_analysis[self.NAME] = self._get_systemd_config(file_object)
            if self.file_path.endswith(('etc/rc', 'etc/rc.local', 'etc/rc.firsttime', 'etc/rc.securelevel')):
                file_object.processed_analysis[self.NAME] = self._get_rc_config(file_object)
            if self.file_path.endswith('etc/initscript'):
                file_object.processed_analysis[self.NAME] = self._get_initscript_config(file_object)
            if 'etc/init/' in self.file_path or 'etc/event.d/' in self.file_path:
                file_object.processed_analysis[self.NAME] = self._get_upstart_config(file_object)
            if 'etc/service/' in self.file_path or 'etc/sv/' in self.file_path:
                file_object.processed_analysis[self.NAME] = self._get_runit_config(file_object)
            if 'etc/init.d/' in self.file_path or 'etc/rc.d/' in self.file_path:
                file_object.processed_analysis[self.NAME] = self._get_sysvinit_config(file_object)
        else:
            file_object.processed_analysis[self.NAME] = dict()
            file_object.processed_analysis[self.NAME]['summary'] = list()
        return file_object

    @staticmethod
    def _findall_regex(pattern, content):
        regex_compiled = re.compile(pattern, re.MULTILINE)
        return regex_compiled.findall(content)

    @staticmethod
    def _add_quotes(unquoted_list):
        return list(map(lambda string: ''.join(['"', string, '"']), unquoted_list))
