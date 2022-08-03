import json
import logging
import subprocess
from pathlib import Path
from subprocess import PIPE, STDOUT
from typing import Dict, List, Tuple

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.typing import JsonDict
from objects.file import FileObject

SHELL_SCRIPT = Path(get_src_dir()) / 'bin' / 'checksec'


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'exploit_mitigations'
    DESCRIPTION = 'analyses ELF binaries within a firmware for present exploit mitigation techniques'
    DEPENDENCIES = ['file_type']
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']
    VERSION = '0.1.6'
    FILE = __file__

    def additional_setup(self):
        if not SHELL_SCRIPT.is_file():
            raise RuntimeError(f'checksec not found at path {SHELL_SCRIPT}. Please re-run the backend installation.')

    def do_analysis(self, file_object: FileObject) -> JsonDict:
        try:
            file_type = file_object.processed_analysis['file_type'].get('result', {}).get('full', '')
            if 'ELF' in file_type:
                return check_mitigations(file_object.file_path)
            return {}
        except (IndexError, json.JSONDecodeError, ValueError) as error:
            logging.exception('Error occurred during exploit_mitigations analysis')
            return {'failed': f'Error during analysis: {error}'}

    @staticmethod
    def create_summary(analysis_result: JsonDict) -> List[str]:
        return analysis_result.pop('summary', [])


def execute_checksec_script(file_path):
    checksec_process = subprocess.run(
        f'{SHELL_SCRIPT} --file={file_path} --format=json --extended',
        shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True
    )
    if checksec_process.returncode != 0:
        raise ValueError(f'Checksec script exited with non-zero return code {checksec_process.returncode}')
    return json.loads(checksec_process.stdout)[str(file_path)]


def check_mitigations(file_path):
    mitigations, summary = {}, []
    checksec_result = execute_checksec_script(file_path)

    for check in [check_relro, check_nx, check_canary, check_pie, check_fortify_source, check_clang_cfi,
                  check_clang_safestack, check_stripped_symbols, check_runpath, check_rpath]:
        analysis_result, summary_item = check(checksec_result)
        mitigations.update(analysis_result)
        summary.extend(summary_item)

    mitigations.update({'summary': summary})
    return mitigations


def check_relro(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['relro'] == 'full':
        return {'RELRO': 'fully enabled'}, ['RELRO fully enabled']
    if checksec_result['relro'] == 'partial':
        return {'RELRO': 'partially enabled'}, ['RELRO partially enabled']
    if checksec_result['relro'] == 'no':
        return {'RELRO': 'disabled'}, ['RELRO disabled']
    return {}, []


def check_fortify_source(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['fortify_source'] == 'yes':
        return {'FORTIFY_SOURCE': 'enabled'}, ['FORTIFY_SOURCE enabled']
    if checksec_result['fortify_source'] == 'no':
        return {'FORTIFY_SOURCE': 'disabled'}, ['FORTIFY_SOURCE disabled']
    return {}, []


def check_pie(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['pie'] == 'yes':
        return {'PIE': 'enabled'}, ['PIE enabled']
    if checksec_result['pie'] == 'no':
        return {'PIE': 'disabled'}, ['PIE disabled']
    if checksec_result['pie'] == 'dso':
        return {'PIE': 'DSO'}, ['PIE/DSO present']
    if checksec_result['pie'] == 'rel':
        return {'PIE': 'REL'}, ['PIE/REL present']
    return {'PIE': 'invalid ELF file'}, ['PIE - invalid ELF file']


def check_nx(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['nx'] == 'yes':
        return {'NX': 'enabled'}, ['NX enabled']
    if checksec_result['nx'] == 'no':
        return {'NX': 'disabled'}, ['NX disabled']
    return {}, []


def check_canary(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['canary'] == 'yes':
        return {'CANARY': 'enabled'}, ['CANARY enabled']
    if checksec_result['canary'] == 'no':
        return {'CANARY': 'disabled'}, ['CANARY disabled']
    return {}, []


def check_clang_cfi(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['clangcfi'] == 'yes':
        return {'CLANGCFI': 'enabled'}, ['CLANGCFI enabled']
    if checksec_result['clangcfi'] == 'no':
        return {'CLANGCFI': 'disabled'}, ['CLANGCFI disabled']
    return {}, []


def check_clang_safestack(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['safestack'] == 'yes':
        return {'SAFESTACK': 'enabled'}, ['SAFESTACK enabled']
    if checksec_result['safestack'] == 'no':
        return {'SAFESTACK': 'disabled'}, ['SAFESTACK disabled']
    return {}, []


def check_rpath(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['rpath'] == 'yes':
        return {'RPATH': 'enabled'}, ['RPATH enabled']
    if checksec_result['rpath'] == 'no':
        return {'RPATH': 'disabled'}, ['RPATH disabled']
    return {}, []


def check_runpath(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['runpath'] == 'yes':
        return {'RUNPATH': 'enabled'}, ['RUNPATH enabled']
    if checksec_result['runpath'] == 'no':
        return {'RUNPATH': 'disabled'}, ['RUNPATH disabled']
    return {}, []


def check_stripped_symbols(checksec_result: Dict[str, str]) -> Tuple[dict, List[str]]:
    if checksec_result['symbols'] == 'yes':
        return {'STRIPPED SYMBOLS': 'disabled'}, ['STRIPPED SYMBOLS disabled']
    if checksec_result['symbols'] == 'no':
        return {'STRIPPED SYMBOLS': 'enabled'}, ['STRIPPED SYMBOLS enabled']
    return {}, []
