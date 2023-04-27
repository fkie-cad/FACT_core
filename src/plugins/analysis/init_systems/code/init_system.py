import re

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.data_conversion import make_unicode_string
from helperFunctions.virtual_file_path import get_top_of_virtual_path
from objects.file import FileObject

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
    VERSION = '0.4.2'
    FILE = __file__

    def additional_setup(self):
        self.content = None

    @staticmethod
    def _is_text_file(file_object):
        return file_object.processed_analysis['file_type']['result']['mime'] in ['text/plain']

    @staticmethod
    def _get_file_path(file_object: FileObject):
        root_uid = file_object.root_uid or list(file_object.parent_firmware_uids)[0]
        return get_top_of_virtual_path(file_object.virtual_file_path[root_uid][0])

    def _get_systemd_config(self, file_object):
        result = {}
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
        result = {}
        matches = self._findall_regex(r'^(?!#)(.+)', self.content)
        if matches:
            result['script'] = '\n'.join(matches)
        result['init_type'] = ['rc']
        result['summary'] = result['init_type']
        return result

    def _get_inittab_config(self, _):
        result = {}
        matches_sysinit = self._findall_regex(r'^[^#].*(?<=sysinit:)([^#].*)', self.content)
        matches_respawn = self._findall_regex(r'^[^#].*(?<=respawn:)([^#].*)', self.content)
        all_matches = []
        all_matches.extend(list(matches_sysinit))
        all_matches.extend(list(matches_respawn))
        if all_matches:
            result['inittab'] = '\n'.join(all_matches)
            result['init_type'] = ['inittab']
            result['summary'] = result['init_type']
        return result

    def _get_initscript_config(self, _):
        result = {}
        matches = self._findall_regex(r'^(?!#)(.+)', self.content)
        if matches:
            result['script'] = '\n'.join(matches)
        result['init_type'] = ['initscript']
        result['summary'] = result['init_type']
        return result

    def _get_upstart_config(self, file_object):
        result = {}
        match_description = self._findall_regex(r'^[^#].*(?<=description)\s*(.*)', self.content)
        match_exec = self._findall_regex(r'[^#]^exec\s*((?:.*\\\n)*.*)', self.content)
        match_pre_start = self._findall_regex(
            r'(?<=pre-start script\n)(?:(?:[\S\s]*?)[\n]*)(?=\nend script)', self.content
        )
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
        result = {}
        match_exec = self._findall_regex(r'^([^#](?:.*\\\n)*.*)', self.content)
        if match_exec:
            result['script'] = '\n'.join(match_exec)
        result['description'] = [file_object.file_name]
        result['init_type'] = ['RunIt']
        result['summary'] = result['init_type']
        return result

    def _get_sysvinit_config(self, file_object):
        result = {}
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
            file_path = self._get_file_path(file_object)
            self.content = make_unicode_string(file_object.binary)  # pylint: disable=attribute-defined-outside-init
            if '/inittab' in file_path:
                file_object.processed_analysis[self.NAME] = self._get_inittab_config(file_object)
            if 'systemd/system/' in file_path:
                file_object.processed_analysis[self.NAME] = self._get_systemd_config(file_object)
            if file_path.endswith(('etc/rc', 'etc/rc.local', 'etc/rc.firsttime', 'etc/rc.securelevel')):
                file_object.processed_analysis[self.NAME] = self._get_rc_config(file_object)
            if file_path.endswith('etc/initscript'):
                file_object.processed_analysis[self.NAME] = self._get_initscript_config(file_object)
            if 'etc/init/' in file_path or 'etc/event.d/' in file_path:
                file_object.processed_analysis[self.NAME] = self._get_upstart_config(file_object)
            if 'etc/service/' in file_path or 'etc/sv/' in file_path:
                file_object.processed_analysis[self.NAME] = self._get_runit_config(file_object)
            if 'etc/init.d/' in file_path or 'etc/rc.d/' in file_path:
                file_object.processed_analysis[self.NAME] = self._get_sysvinit_config(file_object)
        else:
            file_object.processed_analysis[self.NAME] = {'summary': []}
        return file_object

    @staticmethod
    def _findall_regex(pattern, content):
        regex_compiled = re.compile(pattern, re.MULTILINE)
        return regex_compiled.findall(content)

    @staticmethod
    def _add_quotes(unquoted_list):
        return [f'"{element}"' for element in unquoted_list]
