import logging
import re
from base64 import b64decode
from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable, List

from docker.types import Mount

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.tag import TagColor
from objects.file import FileObject
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

JOHN_PATH = Path(__file__).parent.parent / 'bin' / 'john'
JOHN_POT = Path(__file__).parent.parent / 'bin' / 'john.pot'
WORDLIST_PATH = Path(get_src_dir()) / 'bin' / 'passwords.txt'
USER_NAME_REGEX = br'[a-zA-Z][a-zA-Z0-9_-]{2,15}'
UNIX_REGEXES = [
    USER_NAME_REGEX + br':[^:]?:\d+:\d*:[^:]*:[^:]*:[^\n ]*',
    USER_NAME_REGEX + br':\$[1256][ay]?\$[a-zA-Z0-9\./+]+\$[a-zA-Z0-9\./+]{16,128}={0,2}',  # MD5 / Blowfish / SHA
    USER_NAME_REGEX + br':[a-zA-Z0-9\./=]{13}:\d*:\d*:'  # DES
]
HTPASSWD_REGEXES = [
    USER_NAME_REGEX + br':\$apr1\$[a-zA-Z0-9\./+=]+\$[a-zA-Z0-9\./+]{22}',  # MD5 apr1
    USER_NAME_REGEX + br':\{SHA\}[a-zA-Z0-9\./+]{27}=',  # SHA-1
]
MOSQUITTO_REGEXES = [br'[a-zA-Z][a-zA-Z0-9_-]{2,15}\:\$6\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/]{86}==']
RESULTS_DELIMITER = '=== Results: ==='


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This plug-in tries to find and crack passwords
    '''
    NAME = 'users_and_passwords'
    DEPENDENCIES = []
    MIME_BLACKLIST = MIME_BLACKLIST_NON_EXECUTABLE
    DESCRIPTION = 'search for UNIX, httpd, and mosquitto password files, parse them and try to crack the passwords'
    VERSION = '0.5.1'
    FILE = __file__

    def process_object(self, file_object: FileObject) -> FileObject:
        if self.NAME not in file_object.processed_analysis:
            file_object.processed_analysis[self.NAME] = {}
        file_object.processed_analysis[self.NAME]['summary'] = []
        self.find_password_entries(file_object, UNIX_REGEXES, generate_unix_entry)
        self.find_password_entries(file_object, HTPASSWD_REGEXES, generate_htpasswd_entry)
        self.find_password_entries(file_object, MOSQUITTO_REGEXES, generate_mosquitto_entry)
        return file_object

    def find_password_entries(self, file_object: FileObject, regex_list: List[bytes], entry_gen_function: Callable):
        for passwd_regex in regex_list:
            passwd_entries = re.findall(passwd_regex, file_object.binary)
            for entry in passwd_entries:
                self.update_file_object(file_object, entry_gen_function(entry))

    def _add_found_password_tag(self, file_object: FileObject, result: dict):
        for password_entry in result:
            if 'password' in result[password_entry]:
                username = password_entry.split(':', 1)[0]
                password = result[password_entry]['password']
                self.add_analysis_tag(
                    file_object, f'{username}_{password}', f'Password: {username}:{password}', TagColor.RED, True,
                )

    def update_file_object(self, file_object: FileObject, result_entry: dict):
        file_object.processed_analysis[self.NAME].update(result_entry)
        file_object.processed_analysis[self.NAME]['summary'].extend(list(result_entry))
        self._add_found_password_tag(file_object, result_entry)


def generate_unix_entry(entry: bytes) -> dict:
    user_name, pw_hash, *_ = entry.split(b':')
    result_entry = {'type': 'unix', 'entry': _to_str(entry)}
    try:
        if pw_hash.startswith(b'$') or _is_des_hash(pw_hash):
            result_entry['password-hash'] = _to_str(pw_hash)
            result_entry['cracked'] = crack_hash(b':'.join((user_name, pw_hash)), result_entry)
    except (IndexError, AttributeError, TypeError):
        logging.warning(f'Unsupported password format: {entry}', exc_info=True)
    return {f'{_to_str(user_name)}:unix': result_entry}


def generate_htpasswd_entry(entry: bytes) -> dict:
    user_name, pw_hash = entry.split(b':')
    result_entry = {'type': 'htpasswd', 'entry': _to_str(entry), 'password-hash': _to_str(pw_hash)}
    result_entry['cracked'] = crack_hash(entry, result_entry)
    return {f'{_to_str(user_name)}:htpasswd': result_entry}


def generate_mosquitto_entry(entry: bytes) -> dict:
    entry_decoded = _to_str(entry)
    user, _, _, salt_hash, passwd_hash, *_ = re.split(r'[:$]', entry_decoded)
    passwd_entry = f'{user}:$dynamic_82${b64decode(passwd_hash).hex()}$HEX${b64decode(salt_hash).hex()}'
    result_entry = {'type': 'mosquitto', 'entry': entry_decoded, 'password-hash': passwd_hash}
    result_entry['cracked'] = crack_hash(passwd_entry.encode(), result_entry, '--format=dynamic_82')
    return {f'{user}:mosquitto': result_entry}


def _is_des_hash(pw_hash: str) -> bool:
    return len(pw_hash) == 13


def crack_hash(passwd_entry: bytes, result_entry: dict, format_term: str = '') -> bool:
    with NamedTemporaryFile() as fp:
        fp.write(passwd_entry)
        fp.seek(0)
        john_process = run_docker_container(
            'fact/john:alpine-3.14',
            command=f'/work/input_file {format_term}',
            mounts=[
                Mount('/work/input_file', fp.name, type='bind'),
                Mount('/root/.john/john.pot', str(JOHN_POT), type='bind'),
            ],
            logging_label='users_and_passwords',
        )
        result_entry['log'] = john_process.stdout
        output = parse_john_output(john_process.stdout)
    if output:
        if any('0 password hashes cracked' in line for line in output):
            result_entry['ERROR'] = 'hash type is not supported'
            return False
        with suppress(KeyError):
            result_entry['password'] = output[0].split(':')[1]
            return True
    return False


def parse_john_output(john_output: str) -> List[str]:
    if RESULTS_DELIMITER in john_output:
        start_offset = john_output.find(RESULTS_DELIMITER) + len(RESULTS_DELIMITER) + 1  # +1 is '\n' after delimiter
        return [line for line in john_output[start_offset:].split('\n') if line]
    return []


def _to_str(byte_str: bytes) -> str:
    '''result entries must be converted from `bytes` to `str` in order to be saved as JSON'''
    return byte_str.decode(errors='replace')
