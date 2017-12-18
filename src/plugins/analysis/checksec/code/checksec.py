from analysis.PluginBase import BasePlugin
from common_helper_process import execute_shell_command
import re

READELF_FULL = 'readelf -W -l -d -s -h {} '

'''
TODO: check_fortify routine in future update
'''


class AnalysisPlugin(BasePlugin):
    NAME = "exploit_mitigations"
    DESCRIPTION = "analyses ELF binaries within a firmware for present exploit mitigation techniques"
    DEPENDENCYS = ['file_type']
    VERSION = "0.1"

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        try:
            if re.search(r'.*elf.*', file_object.processed_analysis['file_type']['full'].lower()) is not None:
                mitigation_dict, mitigation_dict_summary = check_mitigations(file_object.file_path)
                file_object.processed_analysis[self.NAME] = mitigation_dict
                file_object.processed_analysis[self.NAME]['summary'] = list(mitigation_dict_summary.keys())
            else:
                file_object.processed_analysis[self.NAME]['summary'] = []
        except:
            file_object.processed_analysis[self.NAME]['summary'] = ['Error - Firmware could not be processed properly']
        return file_object


def get_readelf_result(path):
    readelf_full = execute_shell_command(READELF_FULL.format(path))
    return readelf_full


def check_relro(file_path, dict_res, dict_sum, readelf):
    if re.search(r'GNU_RELRO', readelf):
        if re.search(r'BIND_NOW', readelf):
            dict_sum.update({'RELRO fully enabled': file_path})
            dict_res.update({'RELRO': 'fully enabled'})
        else:
            dict_sum.update({'RELRO partially enabled': file_path})
            dict_res.update({'RELRO': 'partially enabled'})
    else:
        dict_sum.update({'RELRO disabled': file_path})
        dict_res.update({'RELRO': 'disabled'})


def check_pie(file_path, dict_res, dict_sum, readelf):
    if re.search(r'Type:\s*EXEC', readelf):
        dict_sum.update({'PIE disabled': file_path})
        dict_res.update({'PIE': 'disabled'})
    elif re.search(r'Type:\s*DYN', readelf):
        if re.search(r'\(DEBUG\)', readelf):
            dict_sum.update({'PIE enabled': file_path})
            dict_res.update({'PIE': 'enabled'})
        else:
            dict_sum.update({'PIE/DSO present': file_path})
            dict_res.update({'PIE': 'DSO'})
    else:
        dict_sum.update({'PIE - Not a valid ELF file': file_path})
        dict_res.update({'PIE': 'Not a valid ELF file'})


def check_nx_or_canary(file_path, dict_res, dict_sum, readelf, flag):
    if flag == 'NX':
        mitigation_off = re.search(r'GNU_STACK[\s0-9a-z]*RWE', readelf)
    elif flag == 'Canary':
        canary_on = re.search(r'__stack_chk_fail', readelf)
        mitigation_off = not canary_on
    else:
        pass
    if mitigation_off:
        dict_sum.update({'{} disabled'.format(flag): file_path})
        dict_res.update({flag: 'disabled'})
    elif not mitigation_off:
        dict_sum.update({'{} enabled'.format(flag): file_path})
        dict_res.update({flag: 'enabled'})
    else:
        pass


def check_mitigations(file_path):
    dict_res, dict_sum = {}, {}
    readelf_results = get_readelf_result(file_path)
    check_relro(file_path, dict_res, dict_sum, readelf_results)
    check_nx_or_canary(file_path, dict_res, dict_sum, readelf_results, 'NX')
    check_nx_or_canary(file_path, dict_res, dict_sum, readelf_results, 'Canary')
    check_pie(file_path, dict_res, dict_sum, readelf_results)
    return dict_res, dict_sum
