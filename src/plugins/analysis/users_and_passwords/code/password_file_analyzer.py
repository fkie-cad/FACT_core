import logging
import os
import re
import sys
from contextlib import suppress
from tempfile import NamedTemporaryFile

from common_helper_process import execute_shell_command

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.fileSystem import get_src_dir


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This Plugin trys to find and crack passwords
    '''
    NAME = 'users_and_passwords'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['audio', 'filesystem', 'image', 'video']
    DESCRIPTION = 'search for UNIX and httpd password files, parse them and try to crack the passwords'
    VERSION = '0.4.1'

    wordlist_path = os.path.join(get_src_dir(), 'bin/passwords.txt')

    def __init__(self, plugin_administrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config

        # additional init stuff can go here
        super().__init__(plugin_administrator, config=config, recursive=recursive, no_multithread=True, plugin_path=__file__)

    def process_object(self, file_object):
        '''
        This function must be implemented by the plugin.
        Analysis result must be a dict stored in file_object.processed_analysis[self.NAME]
        If you want to propagate results to parent objects store a list of strings 'summary' entry of your result dict
        '''
        if self.NAME not in file_object.processed_analysis:
            file_object.processed_analysis[self.NAME] = {}
        file_object.processed_analysis[self.NAME]['summary'] = []

        for passwd_regex in [
            b'[a-zA-Z][a-zA-Z0-9_-]{2,15}:[^:]?:\\d+:\\d*:[^:]*:[^:]*:[^\n ]*',
            b'[a-zA-Z][a-zA-Z0-9_-]{2,15}:\\$[^\\$]+\\$[^\\$]+\\$[a-zA-Z0-9\\./]{16,128}'
        ]:
            passwd_entries = re.findall(passwd_regex, file_object.binary)
            if passwd_entries:
                result = self._generate_analysis_entry(passwd_entries)
                file_object.processed_analysis[self.NAME].update(result)
                file_object.processed_analysis[self.NAME]['summary'] += list(result.keys())
        return file_object

    def _generate_analysis_entry(self, passwd_entries):
        result = {}
        for entry in [e.split(b':') for e in passwd_entries]:
            key = entry[0].decode(encoding='utf_8', errors='replace')
            result[key] = {'entry': b':'.join(entry).decode(encoding='utf_8', errors='replace')}
            try:
                if entry[1][0] == ord('$'):
                    result[key]['password-hash'] = entry[1].decode(encoding='utf_8', errors='replace')
                    cracked_pw = self._crack_hash(entry, result, key)
                    result[key]['cracked'] = True if cracked_pw else False
            except Exception as e:
                logging.error('Invalid Format: {} - {}'.format(sys.exc_info()[0].__name__, e))
        return result

    def _crack_hash(self, passwd_entry, result_dict, key):
        with NamedTemporaryFile() as fp:
            fp.write(b':'.join(passwd_entry[:2]))
            fp.seek(0)
            result_dict[key]['log'] = execute_shell_command('john --wordlist={} {}'.format(self.wordlist_path, fp.name))
            output = execute_shell_command('john --show {}'.format(fp.name)).split('\n')
        if len(output) > 2:
            with suppress(KeyError):
                result_dict[key]['password'] = output[0].split(':')[1]
                return True
        return False
