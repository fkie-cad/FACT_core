import json
import os
import re
from difflib import SequenceMatcher

import lief
from common_helper_files import get_dir_of_file

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.tag import TagColor

TEMPLATE_FILE_PATH = os.path.join(get_dir_of_file(__file__), '../internal/matching_template.json')


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'elf_analysis'
    DESCRIPTION = 'Analyzes and tags ELF executables and libraries'
    DEPENDENCIES = ['file_type']
    VERSION = '0.2'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        elf_dict, parsed_binary = self._analyze_elf(file_object)
        file_object.processed_analysis[self.NAME] = {'Output': elf_dict}
        self.create_tags(parsed_binary, file_object)
        file_object.processed_analysis[self.NAME]['summary'] = list(elf_dict.keys())
        return file_object

    @staticmethod
    def _load_template_file_as_json_obj(path):
        with open(path, 'r') as f:
            data = json.load(f)
        return data

    @staticmethod
    def _get_tags_from_library_list(json_items, key, library_list, tag_list):
        for lib, item in [(lib, item) for lib in library_list for item in json_items]:
            if re.search(item, lib):
                tag_list.append(key)
            else:
                continue
        return tag_list

    @staticmethod
    def _get_tags_from_function_list(function_list, json_items, key, tag_list):
        for func, i in [(func, i) for func in function_list for i in json_items]:
            if i.lower() in func.lower() and SequenceMatcher(None, i, func).ratio() >= 0.85:
                tag_list.append(key)
            else:
                continue
        return tag_list

    def _get_tags(self, library_list, function_list):
        json_template = self._load_template_file_as_json_obj(TEMPLATE_FILE_PATH)
        tag_list = []
        for key in json_template:
            if key not in tag_list:
                json_items = json_template[key]
                self._get_tags_from_function_list(function_list, json_items, key, tag_list)
                self._get_tags_from_library_list(json_items, key, library_list, tag_list)
        return list(set(tag_list))

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
        if tag is 'crypto':
            return TagColor.RED
        elif tag is 'file_system':
            return TagColor.BLUE
        elif tag is 'network':
            return TagColor.ORANGE
        elif tag is 'memory_operations':
            return TagColor.GREEN
        elif tag is 'randomize':
            return TagColor.LIGHT_BLUE
        else:
            return TagColor.GRAY

    def create_tags(self, parsed_bin, file_object):
        all_libs = self._get_symbols_version_entries(parsed_bin.symbols_version)
        all_libs.extend(parsed_bin.libraries)
        all_funcs = self._get_relevant_imp_functions(parsed_bin.imported_functions)
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
                       'imported_functions', 'libraries', 'symbols_version') and binary_json_dict[key]:
                elf_dict[key] = binary_json_dict[key]

    def _analyze_elf(self, file_object):
        elf_dict = {}
        try:
            parsed_binary = lief.parse(file_object.file_path)
            binary_json_dict = json.loads(lief.to_json_from_abstract(parsed_binary))
            if parsed_binary.exported_functions:
                binary_json_dict['exported_functions'] = parsed_binary.exported_functions
            if parsed_binary.imported_functions:
                binary_json_dict['imported_functions'] = parsed_binary.imported_functions
            if parsed_binary.libraries:
                binary_json_dict['libraries'] = parsed_binary.libraries
        except TypeError:
            print('Type Error')
            return elf_dict
        except lief.bad_file:
            print('Bad File, UID: ', file_object.get_uid())
            return elf_dict

        self.get_final_analysis_dict(binary_json_dict, elf_dict)
        return elf_dict, parsed_binary
