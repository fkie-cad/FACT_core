import logging
import os
import re
from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from base64 import b64decode

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
    DESCRIPTION = 'search for UNIX, httpd, and mosquitto password files, parse them and try to crack the passwords'
    VERSION = '0.4.5'

    wordlist_path = os.path.join(get_src_dir(), 'bin/passwords.txt')

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, no_multithread=True, plugin_path=__file__)

    def process_object(self, file_object):
        if self.NAME not in file_object.processed_analysis:
            file_object.processed_analysis[self.NAME] = {}
        file_object.processed_analysis[self.NAME]['summary'] = []
        self.find_shadow_entries(file_object)
        self.find_mosquitto_entries(file_object)
        return file_object

    def find_shadow_entries(self, file_object):
        for passwd_regex in [
                b'[a-zA-Z][a-zA-Z0-9_-]{2,15}:[^:]?:\\d+:\\d*:[^:]*:[^:]*:[^\n ]*',
                b'[a-zA-Z][a-zA-Z0-9_-]{2,15}:\\$[^\\$]+\\$[^\\$]+\\$[a-zA-Z0-9\\./+]{16,128}={0,3}'
        ]:
            passwd_entries = re.findall(passwd_regex, file_object.binary)
            if passwd_entries:
                result = self._generate_analysis_entry(passwd_entries, file_object.uid)
                file_object.processed_analysis[self.NAME].update(result)
                file_object.processed_analysis[self.NAME]['summary'] += list(result.keys())
                self._add_found_password_tag(file_object, result)

    def find_mosquitto_entries(self, file_object):
        for passwd_regex in [br'[a-zA-Z][a-zA-Z0-9_-]{2,15}\:\$6\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/]{86}==']:
            passwd_entries = re.findall(passwd_regex, file_object.binary)
            if passwd_entries:
                result = self._generate_mosquitto_entry(passwd_entries)
                file_object.processed_analysis[self.NAME].update(result)
                file_object.processed_analysis[self.NAME]['summary'] += list(result.keys())
                self._add_found_password_tag(file_object, result)

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

    def _generate_analysis_entry(self, passwd_entries, uid: str):
        result = {}
        for entry in [e.split(b':') for e in passwd_entries]:
            key = entry[0].decode(encoding='utf_8', errors='replace')
            result_entry = result['{}:unix'.format(key)] = {}
            result_entry['entry'] = b':'.join(entry).decode(encoding='utf_8', errors='replace')
            try:
                if entry[1][0] == ord('$'):
                    result_entry['password-hash'] = entry[1].decode(encoding='utf_8', errors='replace')
                    cracked_pw = self._crack_hash(entry, result_entry)
                    result_entry['cracked'] = bool(cracked_pw)
            except (IndexError, AttributeError, TypeError):
                logging.warning('Unsupported Format: {}'.format(uid), exc_info=True)
        return result

    def _generate_mosquitto_entry(self, passwd_entries):
        result = {}
        for entry in [m.split(b'$') for m in passwd_entries]:
            user = entry[0].decode(encoding='utf_8', errors='replace')[:-1]
            salt_hash = entry[2].decode(encoding='utf_8', errors='replace')
            passwd_hash = entry[3].decode(encoding='utf_8', errors='replace')
            passwd_entry = '{}:$dynamic_82${}$HEX${}'.format(user, b64decode(passwd_hash).hex(), b64decode(salt_hash).hex())
            result_entry = result['{}:mosquitto'.format(user)] = {}
            result_entry['entry'] = b'$'.join(entry).decode(encoding='utf_8', errors='replace')
            result_entry['password-hash'] = passwd_hash
            cracked_pw = self._crack_mosquitto_hash(passwd_entry, result_entry)
            result_entry['cracked'] = bool(cracked_pw)
        return result

    def _crack_hash(self, passwd_entry, result_entry):
        with NamedTemporaryFile() as fp:
            fp.write(b':'.join(passwd_entry[:2]))
            fp.seek(0)
            result_entry['log'] = execute_shell_command('john --wordlist={} {}'.format(self.wordlist_path, fp.name))
            output = execute_shell_command('john --show {}'.format(fp.name)).split('\n')
        if len(output) > 2:
            with suppress(KeyError):
                if '0 password hashes cracked' in output[-2]:
                    result_entry['ERROR'] = 'hash type is not supported'
                    return False
                result_entry['password'] = output[0].split(':')[1]
                return True
        return False

    @staticmethod
    def _crack_mosquitto_hash(passwd_entry, result_entry):
        with NamedTemporaryFile() as fp:
            fp.write(passwd_entry.encode())
            fp.seek(0)
            result_entry['log'] = execute_shell_command('john {} --format=dynamic_82'.format(fp.name))
            output = execute_shell_command('john {} --show --format=dynamic_82'.format(fp.name)).split('\n')
        if len(output) > 2:
            with suppress(KeyError):
                if '0 password hashes cracked' in output[-2]:
                    result_entry['ERROR'] = 'hash type is not supported'
                    return False
                result_entry['password'] = output[0].split(':')[1]
                return True
        return False
