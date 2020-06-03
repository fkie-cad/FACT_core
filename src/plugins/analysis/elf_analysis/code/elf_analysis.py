import json
import logging
import os
import re
from difflib import SequenceMatcher

import lief
from common_helper_files import get_dir_of_file

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.hash import normalize_lief_items
from helperFunctions.tag import TagColor

TEMPLATE_FILE_PATH = os.path.join(get_dir_of_file(__file__), '../internal/matching_template.json')

# pylint: disable=c-extension-no-member


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'elf_analysis'
    DESCRIPTION = 'Analyzes and tags ELF executables and libraries'
    DEPENDENCIES = ['file_type']
    VERSION = '0.3'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']

    def __init__(self, plugin_administrator, config=None, recursive=True, offline_testing=False):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__, offline_testing=offline_testing)

    def process_object(self, file_object):
        try:
            elf_dict, parsed_binary = self._analyze_elf(file_object)
            file_object.processed_analysis[self.NAME] = {'Output': elf_dict}
            self.create_tags(parsed_binary, file_object)
            file_object.processed_analysis[self.NAME]['summary'] = list(elf_dict.keys())
        except RuntimeError:
            logging.error('lief could not parse {}'.format(file_object.uid))
            file_object.processed_analysis[self.NAME] = {'Output': {}}
        return file_object

    @staticmethod
    def _load_template_file_as_json_obj(path: str) -> dict:
        with open(path, 'r') as fd:
            data = json.load(fd)
        return data

    @staticmethod
    def _get_tags_from_library_list(libraries: list, behaviour_class: str, indicators: list, tags: list):
        for library, indicator in ((lib, ind) for lib in libraries for ind in indicators):
            if re.search(indicator, library):
                tags.append(behaviour_class)

    @staticmethod
    def _get_tags_from_function_list(functions: list, behaviour_class: str, indicators: list, tags: list):
        for function, indicator in ((f, i) for f in functions for i in indicators):
            if indicator.lower() in function.lower() and SequenceMatcher(None, indicator, function).ratio() >= 0.85:
                tags.append(behaviour_class)

    def _get_tags(self, libraries: list, functions: list) -> list:
        behaviour_classes = self._load_template_file_as_json_obj(TEMPLATE_FILE_PATH)
        tags = list()
        for behaviour_class in behaviour_classes:
            if behaviour_class not in tags:
                behaviour_indicators = behaviour_classes[behaviour_class]
                self._get_tags_from_function_list(functions, behaviour_class, behaviour_indicators, tags)
                self._get_tags_from_library_list(libraries, behaviour_class, behaviour_indicators, tags)
        return list(set(tags))

    @staticmethod
    def _get_symbols_version_entries(symbol_versions):
        imported_libs = []
        for sv in symbol_versions:
            if str(sv) != '* Local *' and str(sv) != "* Global *":
                imported_libs.append(str(sv).split('(')[0])
        return list(set(imported_libs))

    @staticmethod
    def _get_relevant_imp_functions(imp_functions):
        imp_functions[:] = [x for x in imp_functions if not x.startswith('__')]
        return imp_functions

    @staticmethod
    def _get_color_codes(tag):
        if tag == 'crypto':
            return TagColor.RED
        if tag == 'file_system':
            return TagColor.BLUE
        if tag == 'network':
            return TagColor.ORANGE
        if tag == 'memory_operations':
            return TagColor.GREEN
        if tag == 'randomize':
            return TagColor.LIGHT_BLUE
        return TagColor.GRAY

    def create_tags(self, parsed_bin, file_object):
        all_libs = self._get_symbols_version_entries(normalize_lief_items(parsed_bin.symbols_version))
        all_libs.extend(normalize_lief_items(parsed_bin.libraries))
        all_funcs = self._get_relevant_imp_functions(normalize_lief_items(parsed_bin.imported_functions))
        for entry in self._get_tags(all_libs, all_funcs):
            self.add_analysis_tag(
                file_object=file_object,
                tag_name=entry,
                value=entry,
                color=self._get_color_codes(entry),
                propagate=False
            )

    @staticmethod
    def get_final_analysis_dict(binary_json_dict, elf_dict):
        for key in binary_json_dict:
            if key in ('header', 'segments', 'sections', 'dynamic_entries', 'exported_functions',
                       'imported_functions', 'libraries', 'symbols_version')\
                    and binary_json_dict[key]:
                elf_dict[key] = binary_json_dict[key]

    def _analyze_elf(self, file_object):
        elf_dict = {}
        try:
            parsed_binary = lief.parse(file_object.file_path)
            binary_json_dict = json.loads(lief.to_json_from_abstract(parsed_binary))
            if parsed_binary.exported_functions:
                binary_json_dict['exported_functions'] = normalize_lief_items(parsed_binary.exported_functions)
            if parsed_binary.imported_functions:
                binary_json_dict['imported_functions'] = normalize_lief_items(parsed_binary.imported_functions)
            if parsed_binary.libraries:
                binary_json_dict['libraries'] = normalize_lief_items(parsed_binary.libraries)
        except (TypeError, lief.bad_file) as error:
            logging.error('Bad file for lief/elf analysis {}. {}'.format(file_object.uid, error))
            return elf_dict

        self.get_final_analysis_dict(binary_json_dict, elf_dict)
        return elf_dict, parsed_binary
