from __future__ import annotations

import json
import logging
import re
from difflib import SequenceMatcher
from pathlib import Path

import lief

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.hash import normalize_lief_items
from helperFunctions.tag import TagColor
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from objects.file import FileObject

LIEF_DATA_ENTRIES = (
    'dynamic_entries',
    'exported_functions',
    'header',
    'imported_functions',
    'libraries',
    'sections',
    'segments',
    'symbols_version',
)
TEMPLATE_FILE_PATH = Path(__file__).parent.parent / 'internal/matching_template.json'
BEHAVIOUR_CLASSES: dict[str, list[str]] = json.loads(TEMPLATE_FILE_PATH.read_text())


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'elf_analysis'
    DESCRIPTION = 'Analyzes and tags ELF executables and libraries'
    VERSION = '0.3.4'
    MIME_WHITELIST = [  # noqa: RUF012
        'application/x-executable',
        'application/x-pie-executable',
        'application/x-object',
        'application/x-sharedlib',
    ]
    FILE = __file__

    def process_object(self, file_object: FileObject):
        try:
            elf_dict, parsed_binary = self._analyze_elf(file_object)
            file_object.processed_analysis[self.NAME] = {'Output': elf_dict}
            self.create_tags(parsed_binary, file_object)
            file_object.processed_analysis[self.NAME]['summary'] = list(elf_dict.keys())
        except (RuntimeError, ValueError):
            logging.error(f'lief could not parse {file_object.uid}', exc_info=True)
            file_object.processed_analysis[self.NAME] = {'failed': 'lief could not parse the file'}
        return file_object

    @staticmethod
    def _get_tags_from_library_list(libraries: list[str], behaviour_class: str, indicators: list[str], tags: list[str]):
        for library in libraries:
            for indicator in indicators:
                if re.search(indicator, library):
                    tags.append(behaviour_class)

    @staticmethod
    def _get_tags_from_function_list(
        functions: list[str], behaviour_class: str, indicators: list[str], tags: list[str]
    ):
        for function in functions:
            for indicator in indicators:
                if _function_contains_indicator(function, indicator):
                    tags.append(behaviour_class)

    def _get_tags(self, libraries: list[str], functions: list[str]) -> list[str]:
        tags: list[str] = []
        for behaviour_class, behaviour_indicators in BEHAVIOUR_CLASSES.items():
            if behaviour_class not in tags:
                self._get_tags_from_function_list(functions, behaviour_class, behaviour_indicators, tags)
                self._get_tags_from_library_list(libraries, behaviour_class, behaviour_indicators, tags)
        return list(set(tags))

    @staticmethod
    def _get_symbols_version_entries(symbol_versions: list[str]) -> list[str]:
        imported_libs: set[str] = set()
        for version in symbol_versions:
            if str(version) != '* Local *' and str(version) != '* Global *':
                imported_libs.add(str(version).split('(', maxsplit=1)[0])
        return list(imported_libs)

    @staticmethod
    def _get_relevant_imp_functions(imp_functions: list[str]) -> list[str]:
        return [x for x in imp_functions if not x.startswith('__')]

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

    def create_tags(self, parsed_bin, file_object: FileObject):
        all_libs = self._get_symbols_version_entries(normalize_lief_items(parsed_bin.symbols_version))
        all_libs.extend(normalize_lief_items(parsed_bin.libraries))
        all_funcs = self._get_relevant_imp_functions(normalize_lief_items(parsed_bin.imported_functions))
        for entry in self._get_tags(all_libs, all_funcs):
            self.add_analysis_tag(
                file_object=file_object,
                tag_name=entry,
                value=entry,
                color=self._get_color_codes(entry),
                propagate=False,
            )

    @staticmethod
    def get_final_analysis_dict(binary_json_dict, elf_dict):
        for key in binary_json_dict:
            if key in LIEF_DATA_ENTRIES and binary_json_dict[key]:
                elf_dict[key] = binary_json_dict[key]

    def _analyze_elf(self, file_object: FileObject):
        elf_dict = {}
        try:
            parsed_binary = lief.parse(file_object.file_path)
            binary_json_dict = json.loads(lief.to_json(parsed_binary))
            if parsed_binary.exported_functions:
                binary_json_dict['exported_functions'] = normalize_lief_items(parsed_binary.exported_functions)
            if parsed_binary.imported_functions:
                binary_json_dict['imported_functions'] = normalize_lief_items(parsed_binary.imported_functions)
            if parsed_binary.libraries:
                binary_json_dict['libraries'] = normalize_lief_items(parsed_binary.libraries)
            modinfo_data = self.filter_modinfo(parsed_binary)
            if modinfo_data:
                elf_dict['modinfo'] = modinfo_data

        except (AttributeError, TypeError, lief.bad_file):
            logging.error(f'Bad file for lief/elf analysis {file_object.uid}.', exc_info=True)
            return elf_dict

        self.get_final_analysis_dict(binary_json_dict, elf_dict)
        self._convert_address_values_to_hex(elf_dict)

        return elf_dict, parsed_binary

    @staticmethod
    def _convert_address_values_to_hex(elf_dict):
        for category in {'sections', 'segments'}.intersection(elf_dict):
            for entry in elf_dict[category]:
                for key in {'virtual_address', 'offset'}.intersection(entry):
                    entry[key] = hex(entry[key])

    @staticmethod
    def filter_modinfo(binary) -> list[str] | None:
        # getting the information from the *.ko files .modinfo section
        modinfo = None
        for section in binary.sections:
            if section.name == '.modinfo':
                section_content = bytes(section.content).decode()
                modinfo = [entry for entry in section_content.split('\x00') if entry]
                break
        return modinfo


MIN_SIMILARITY = 0.85


def _function_contains_indicator(function: str, indicator: str) -> bool:
    return (
        indicator.lower() in function.lower() and SequenceMatcher(None, indicator, function).ratio() >= MIN_SIMILARITY
    )
