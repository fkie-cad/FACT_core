import json
import re
from pathlib import Path

from common_helper_process import execute_shell_command

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'exploit_mitigations'
    DESCRIPTION = 'analyses ELF binaries within a firmware for present exploit mitigation techniques'
    DEPENDENCIES = ['file_type']
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']
    VERSION = '0.1.3'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        try:
            if re.search(r'.*elf.*', file_object.processed_analysis['file_type']['full'].lower()) is not None:

                mitigation_dict, mitigation_dict_summary = check_mitigations(file_object.file_path)
                file_object.processed_analysis[self.NAME] = mitigation_dict
                file_object.processed_analysis[self.NAME]['summary'] = list(mitigation_dict_summary.keys())
            else:
                file_object.processed_analysis[self.NAME]['summary'] = []
        except Exception as error:
            file_object.processed_analysis[self.NAME]['summary'] = [
                'Error - Firmware could not be processed properly: {}'.format(error)
            ]
        return file_object


def load_information(file_path):
    dir_checksec = Path(__file__).parent.parent
    print(str(dir_checksec))
    shell_skript = dir_checksec/'shell_skript/checksec'
    print(str(shell_skript))
    install_shell_skript = dir_checksec/'install.sh'
    print(str(install_shell_skript))

    if not shell_skript.exists():
        execute_shell_command([str(install_shell_skript)])

    json_file_information = execute_shell_command(str(shell_skript) + ' --file=' + str(file_path) + ' --format=json --extended')

    dict_file_information = json.loads(json_file_information)

    return dict_file_information


def check_mitigations(file_path):
    dict_res, dict_sum = {}, {}
    dict_file_info = load_information(file_path)

    check_relro(file_path, dict_res, dict_sum, dict_file_info)
    check_nx(file_path, dict_res, dict_sum, dict_file_info)
    check_canary(file_path, dict_res, dict_sum, dict_file_info)
    check_pie(file_path, dict_res, dict_sum, dict_file_info)
    check_fortify_source(file_path, dict_res, dict_sum, dict_file_info)
    # check_selfrando(file_path, dict_res, dict_sum, dict_file_info) # konnte nicht gefunden werden
    check_clang_cfi(file_path, dict_res, dict_sum, dict_file_info)
    check_clang_safestack(file_path, dict_res, dict_sum, dict_file_info)
    check_stripped_symbols(file_path, dict_res, dict_sum, dict_file_info)
    check_runpath(file_path, dict_res, dict_sum, dict_file_info)
    check_rpath(file_path, dict_res, dict_sum, dict_file_info)

    return dict_res, dict_sum


def check_relro(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['relro'] == "full":
        dict_sum.update({'RELRO fully enabled': file_path})
        dict_res.update({'RELRO': 'fully enabled'})

    elif dict_file_info[str(file_path)]['relro'] == "partial":
        dict_sum.update({'RELRO partially enabled': file_path})
        dict_res.update({'RELRO': 'partially enabled'})

    elif dict_file_info[str(file_path)]['relro'] == "no":
        dict_sum.update({'RELRO disabled': file_path})
        dict_res.update({'RELRO': 'disabled'})


def check_fortify_source(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['fortify_source'] == "yes":
        dict_sum.update({'FORTIFY_SOURCE enabled': file_path})
        dict_res.update({'FORTIFY_SOURCE': 'enabled'})

    elif dict_file_info[str(file_path)]['fortify_source'] == "no":
        dict_sum.update({'FORTIFY_SOURCE disabled': file_path})
        dict_res.update({'FORTIFY_SOURCE': 'disabled'})


def check_pie(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['pie'] == "yes":
        dict_sum.update({'PIE enabled': file_path})
        dict_res.update({'PIE': 'enabled'})

    elif dict_file_info[str(file_path)]['pie'] == "no":
        dict_sum.update({'PIE disabled': file_path})
        dict_res.update({'PIE': 'disabled'})

    elif dict_file_info[str(file_path)]['pie'] == "dso":
        dict_sum.update({'PIE/DSO present': file_path})
        dict_res.update({'PIE': 'DSO'})

    elif dict_file_info[str(file_path)]['pie'] == "rel":
        dict_sum.update({'PIE/REL present': file_path})
        dict_res.update({'PIE': 'REL'})

    else:
        dict_sum.update({'PIE - invalid ELF file': file_path})
        dict_res.update({'PIE': 'invalid ELF file'})


def check_nx(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['nx'] == "yes":
        dict_sum.update({'NX enabled': file_path})
        dict_res.update({'NX': 'enabled'})

    elif dict_file_info[str(file_path)]['nx'] == "no":
        dict_sum.update({'NX disabled': file_path})
        dict_res.update({'NX': 'disabled'})


def check_canary(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['canary'] == "yes":
        dict_sum.update({'CANARY enabled': file_path})
        dict_res.update({'CANARY': 'enabled'})

    elif dict_file_info[str(file_path)]['canary'] == "no":
        dict_sum.update({'CANARY disabled': file_path})
        dict_res.update({'CANARY': 'disabled'})


def check_clang_cfi(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['clangcfi'] == "yes":
        dict_sum.update({'CLANGCFI enabled': file_path})
        dict_res.update({'CLANGCFI': 'enabled'})

    elif dict_file_info[str(file_path)]['clangcfi'] == "no":
        dict_sum.update({'CLANGCFI disabled': file_path})
        dict_res.update({'CLANGCFI': 'disabled'})


def check_clang_safestack(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['safestack'] == "yes":
        dict_sum.update({'SAFESTACK enabled': file_path})
        dict_res.update({'SAFESTACK': 'enabled'})

    elif dict_file_info[str(file_path)]['safestack'] == "no":
        dict_sum.update({'SAFESTACK disabled': file_path})
        dict_res.update({'SAFESTACK': 'disabled'})


def check_rpath(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['rpath'] == "yes":
        dict_sum.update({'RPATH enabled': file_path})
        dict_res.update({'RPATH': 'enabled'})

    elif dict_file_info[str(file_path)]['rpath'] == "no":
        dict_sum.update({'RPATH disabled': file_path})
        dict_res.update({'RPATH': 'disabled'})


def check_runpath(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['runpath'] == "yes":
        dict_sum.update({'RUNPATH enabled': file_path})
        dict_res.update({'RUNPATH': 'enabled'})

    elif dict_file_info[str(file_path)]['runpath'] == "no":
        dict_sum.update({'RUNPATH disabled': file_path})
        dict_res.update({'RUNPATH': 'disabled'})


def check_stripped_symbols(file_path, dict_res, dict_sum, dict_file_info):
    if dict_file_info[str(file_path)]['symbols'] == "yes":
        dict_sum.update({'STRIPPED SYMBOLS IN THE BINARY disabled': file_path})
        dict_res.update({'STRIPPED SYMBOLS IN THE BINARY': 'disabled'})

    elif dict_file_info[str(file_path)]['symbols'] == "no":
        dict_sum.update({'STRIPPED SYMBOLS IN THE BINARY enabled': file_path})
        dict_res.update({'STRIPPED SYMBOLS IN THE BINARY': 'enabled'})
