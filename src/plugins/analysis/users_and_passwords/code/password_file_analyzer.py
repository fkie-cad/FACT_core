import logging
import os
import re
from contextlib import suppress
from tempfile import NamedTemporaryFile

from common_helper_process import execute_shell_command

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.tag import TagColor


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This plug-in tries to find and crack passwords
    '''
    NAME = 'users_and_passwords'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['audio', 'filesystem', 'image', 'video']
    DESCRIPTION = 'search for UNIX and httpd password files, parse them and try to crack the passwords'
    VERSION = '0.4.4'

    wordlist_path = os.path.join(get_src_dir(), 'bin/passwords.txt')

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, no_multithread=True, plugin_path=__file__)

    def process_object(self, file_object):
        if self.NAME not in file_object.processed_analysis:
            file_object.processed_analysis[self.NAME] = {}
        file_object.processed_analysis[self.NAME]['summary'] = []

        for passwd_regex in [
                b'[a-zA-Z][a-zA-Z0-9_-]{2,15}:[^:]?:\\d+:\\d*:[^:]*:[^:]*:[^\n ]*',
                b'[a-zA-Z][a-zA-Z0-9_-]{2,15}:\\$[^\\$]+\\$[^\\$]+\\$[a-zA-Z0-9\\./+]{16,128}={0,3}'
        ]:
            passwd_entries = re.findall(passwd_regex, file_object.binary)
            if passwd_entries:
                result = self._generate_analysis_entry(passwd_entries)
                file_object.processed_analysis[self.NAME].update(result)
                file_object.processed_analysis[self.NAME]['summary'] += list(result.keys())
                self._add_found_password_tag(file_object, result)
        return file_object

    def _add_found_password_tag(self, file_object, result):
        for password_entry in result:
            if 'password' in result[password_entry]:
                self.add_analysis_tag(
                    file_object,
                    '{}_{}'.format(password_entry, result[password_entry]['password']),
                    'Password: {}:{}'.format(password_entry, result[password_entry]['password']),
                    TagColor.RED,
                    True
                )

    def _generate_analysis_entry(self, passwd_entries):
        result = {}
        for entry in [e.split(b':') for e in passwd_entries]:
            key = entry[0].decode(encoding='utf_8', errors='replace')
            result[key] = {'entry': b':'.join(entry).decode(encoding='utf_8', errors='replace')}
            try:
                if entry[1][0] == ord('$'):
                    result[key]['password-hash'] = entry[1].decode(encoding='utf_8', errors='replace')
                    cracked_pw = self._crack_hash(entry, result, key)
                    result[key]['cracked'] = bool(cracked_pw)
            except (IndexError, AttributeError, TypeError):
                logging.error('Invalid Format:', exc_info=True)
        return result

    def _crack_hash(self, passwd_entry, result_dict, key):
        with NamedTemporaryFile() as fp:
            fp.write(b':'.join(passwd_entry[:2]))
            fp.seek(0)
            result_dict[key]['log'] = execute_shell_command('john --wordlist={} {}'.format(self.wordlist_path, fp.name))
            output = execute_shell_command('john --show {}'.format(fp.name)).split('\n')
        if len(output) > 2:
            with suppress(KeyError):
                if '0 password hashes cracked' in output[-2]:
                    result_dict[key]['ERROR'] = 'hash type is not supported'
                    return False
                result_dict[key]['password'] = output[0].split(':')[1]
                return True
        return False
