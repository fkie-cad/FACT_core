import json
import re
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.fileSystem import get_src_dir

SHELL_SCRIPT = Path(get_src_dir()) / 'bin' / 'checksec'


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'exploit_mitigations'
    DESCRIPTION = 'analyses ELF binaries within a firmware for present exploit mitigation techniques'
    DEPENDENCIES = ['file_type']
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']
    VERSION = '0.1.5'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config

        if not SHELL_SCRIPT.is_file():
            raise RuntimeError(f'checksec not found at path {SHELL_SCRIPT}. Please re-run the backend installation.')

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        try:
            if re.search(r'.*elf.*', file_object.processed_analysis['file_type']['full'].lower()) is not None:

                mitigation_dict, mitigation_dict_summary = check_mitigations(file_object.file_path)
                file_object.processed_analysis[self.NAME] = mitigation_dict
                file_object.processed_analysis[self.NAME]['summary'] = list(mitigation_dict_summary.keys())
            else:
                file_object.processed_analysis[self.NAME]['summary'] = []
        except (IndexError, json.JSONDecodeError, ValueError) as error:
            file_object.processed_analysis[self.NAME]['summary'] = [
                'Error - Firmware could not be processed properly: {}'.format(error)
            ]
        return file_object


def execute_checksec_script(file_path):
    checksec_result, return_code = execute_shell_command_get_return_code(f'{SHELL_SCRIPT} --file={file_path} --format=json --extended')
    if return_code != 0:
        raise ValueError(f'Checksec script exited with non-zero return code {return_code}')
    return json.loads(checksec_result)[str(file_path)]


def check_mitigations(file_path):
    mitigations, summary = {}, {}
    checksec_result = execute_checksec_script(file_path)

    check_relro(file_path, mitigations, summary, checksec_result)
    check_nx(file_path, mitigations, summary, checksec_result)
    check_canary(file_path, mitigations, summary, checksec_result)
    check_pie(file_path, mitigations, summary, checksec_result)
    check_fortify_source(file_path, mitigations, summary, checksec_result)
    check_clang_cfi(file_path, mitigations, summary, checksec_result)
    check_clang_safestack(file_path, mitigations, summary, checksec_result)
    check_stripped_symbols(file_path, mitigations, summary, checksec_result)
    check_runpath(file_path, mitigations, summary, checksec_result)
    check_rpath(file_path, mitigations, summary, checksec_result)

    return mitigations, summary


def check_relro(file_path, mitigations, summary, checksec_result):
    if checksec_result['relro'] == 'full':
        summary.update({'RELRO fully enabled': file_path})
        mitigations.update({'RELRO': 'fully enabled'})

    elif checksec_result['relro'] == 'partial':
        summary.update({'RELRO partially enabled': file_path})
        mitigations.update({'RELRO': 'partially enabled'})

    elif checksec_result['relro'] == 'no':
        summary.update({'RELRO disabled': file_path})
        mitigations.update({'RELRO': 'disabled'})


def check_fortify_source(file_path, mitigations, summary, checksec_result):
    if checksec_result['fortify_source'] == 'yes':
        summary.update({'FORTIFY_SOURCE enabled': file_path})
        mitigations.update({'FORTIFY_SOURCE': 'enabled'})

    elif checksec_result['fortify_source'] == 'no':
        summary.update({'FORTIFY_SOURCE disabled': file_path})
        mitigations.update({'FORTIFY_SOURCE': 'disabled'})


def check_pie(file_path, mitigations, summary, checksec_result):
    if checksec_result['pie'] == 'yes':
        summary.update({'PIE enabled': file_path})
        mitigations.update({'PIE': 'enabled'})

    elif checksec_result['pie'] == 'no':
        summary.update({'PIE disabled': file_path})
        mitigations.update({'PIE': 'disabled'})

    elif checksec_result['pie'] == 'dso':
        summary.update({'PIE/DSO present': file_path})
        mitigations.update({'PIE': 'DSO'})

    elif checksec_result['pie'] == 'rel':
        summary.update({'PIE/REL present': file_path})
        mitigations.update({'PIE': 'REL'})

    else:
        summary.update({'PIE - invalid ELF file': file_path})
        mitigations.update({'PIE': 'invalid ELF file'})


def check_nx(file_path, mitigations, summary, checksec_result):
    if checksec_result['nx'] == 'yes':
        summary.update({'NX enabled': file_path})
        mitigations.update({'NX': 'enabled'})

    elif checksec_result['nx'] == 'no':
        summary.update({'NX disabled': file_path})
        mitigations.update({'NX': 'disabled'})


def check_canary(file_path, mitigations, summary, checksec_result):
    if checksec_result['canary'] == 'yes':
        summary.update({'CANARY enabled': file_path})
        mitigations.update({'CANARY': 'enabled'})

    elif checksec_result['canary'] == 'no':
        summary.update({'CANARY disabled': file_path})
        mitigations.update({'CANARY': 'disabled'})


def check_clang_cfi(file_path, mitigations, summary, checksec_result):
    if checksec_result['clangcfi'] == 'yes':
        summary.update({'CLANGCFI enabled': file_path})
        mitigations.update({'CLANGCFI': 'enabled'})

    elif checksec_result['clangcfi'] == 'no':
        summary.update({'CLANGCFI disabled': file_path})
        mitigations.update({'CLANGCFI': 'disabled'})


def check_clang_safestack(file_path, mitigations, summary, checksec_result):
    if checksec_result['safestack'] == 'yes':
        summary.update({'SAFESTACK enabled': file_path})
        mitigations.update({'SAFESTACK': 'enabled'})

    elif checksec_result['safestack'] == 'no':
        summary.update({'SAFESTACK disabled': file_path})
        mitigations.update({'SAFESTACK': 'disabled'})


def check_rpath(file_path, mitigations, summary, checksec_result):
    if checksec_result['rpath'] == 'yes':
        summary.update({'RPATH enabled': file_path})
        mitigations.update({'RPATH': 'enabled'})

    elif checksec_result['rpath'] == 'no':
        summary.update({'RPATH disabled': file_path})
        mitigations.update({'RPATH': 'disabled'})


def check_runpath(file_path, mitigations, summary, checksec_result):
    if checksec_result['runpath'] == 'yes':
        summary.update({'RUNPATH enabled': file_path})
        mitigations.update({'RUNPATH': 'enabled'})

    elif checksec_result['runpath'] == 'no':
        summary.update({'RUNPATH disabled': file_path})
        mitigations.update({'RUNPATH': 'disabled'})


def check_stripped_symbols(file_path, mitigations, summary, checksec_result):
    if checksec_result['symbols'] == 'yes':
        summary.update({'STRIPPED SYMBOLS disabled': file_path})
        mitigations.update({'STRIPPED SYMBOLS': 'disabled'})

    elif checksec_result['symbols'] == 'no':
        summary.update({'STRIPPED SYMBOLS enabled': file_path})
        mitigations.update({'STRIPPED SYMBOLS': 'enabled'})
