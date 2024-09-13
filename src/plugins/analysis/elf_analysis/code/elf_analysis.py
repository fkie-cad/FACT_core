from __future__ import annotations

import json
import string
from difflib import SequenceMatcher
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, List, Optional

import lief
from pydantic import BaseModel
from semver import Version

from analysis.plugin import AnalysisPluginV0, Tag
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin
from helperFunctions.hash import normalize_lief_items
from helperFunctions.tag import TagColor

FUNCTION_MATCHING_THRESHOLD = 0.85

if TYPE_CHECKING:
    from io import FileIO

TEMPLATE_FILE_PATH = Path(__file__).parent.parent / 'internal/matching_template.json'
BEHAVIOUR_CLASSES = json.loads(TEMPLATE_FILE_PATH.read_text())
PRINTABLE_BYTES = set(string.printable.encode())
ELF_SEGMENT_FLAGS = {
    'execute': 0x1,  # executable
    'write': 0x2,  # writable
    'read': 0x4,  # readable
}


class ElfHeader(BaseModel):
    entrypoint: int
    file_type: str
    header_size: int
    identity_abi_version: int
    identity_class: str
    identity_data: str
    identity_os_abi: str
    identity_version: str
    machine_type: str
    numberof_sections: int
    object_file_version: str
    processor_flag: int
    processornumberof_segments_flag: int
    program_header_size: int
    program_headers_offset: int
    section_header_size: int
    section_headers_offset: int
    section_name_table_idx: int


class ElfSection(BaseModel):
    flags: List[str]
    name: str
    size: int
    type: str
    offset: int
    virtual_address: int


class ElfSegment(BaseModel):
    file_offset: int
    flags: List[str]
    physical_address: int
    physical_size: int
    type: str
    virtual_address: int
    virtual_size: int


class DynamicEntry(BaseModel):
    tag: str
    value: int
    library: Optional[str] = None
    flags: Optional[List[str]] = None


class ElfSymbol(BaseModel):
    name: str
    offset: int


class InfoSectionData(BaseModel):
    name: str
    contents: str


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    class Schema(BaseModel):
        header: ElfHeader
        sections: List[ElfSection]
        segments: List[ElfSegment]
        dynamic_entries: List[DynamicEntry]
        exported_functions: List[ElfSymbol]
        imported_functions: List[str]
        mod_info: Optional[List[str]]
        note_sections: List[InfoSectionData]
        behavior_classes: List[str]

    def __init__(self):
        metadata = self.MetaData(
            name='elf_analysis',
            description='Analyzes and tags ELF executables and libraries',
            version=Version(1, 0, 0),
            Schema=self.Schema,
            mime_whitelist=[
                'application/x-executable',
                'application/x-pie-executable',
                'application/x-object',
                'application/x-sharedlib',
            ],
        )
        super().__init__(metadata=metadata)

    def analyze(self, file_handle: FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        elf = lief.parse(file_handle.name)
        json_dict = json.loads(lief.to_json(elf))
        _convert_flags(json_dict)
        return self.Schema(
            header=ElfHeader.model_validate(json_dict['header']),
            exported_functions=[ElfSymbol(name=f.name, offset=f.address) for f in elf.exported_functions],
            imported_functions=[f.name for f in elf.imported_functions],
            sections=[ElfSection.model_validate(s) for s in json_dict['sections']],
            segments=[ElfSegment.model_validate(s) for s in json_dict['segments']],
            dynamic_entries=[DynamicEntry.model_validate(e) for e in json_dict['dynamic_entries']],
            note_sections=[c for c in _get_note_sections_content(elf) if c],
            mod_info=_get_modinfo(elf),
            behavior_classes=_get_behavior_classes(elf),
        )

    def summarize(self, result: Schema) -> list[str]:
        keys = ['sections', 'dynamic_entries', 'exported_functions', 'imported_functions', 'note_sections', 'mod_info']
        return [k for k, v in result.model_dump().items() if k in keys and v]

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del summary
        tags = []
        for behaviour_class in result.behavior_classes:
            tags.append(
                Tag(
                    name=behaviour_class,
                    value=behaviour_class,
                    color=self._get_color_codes(behaviour_class),
                    propagate=False,
                )
            )
        return tags

    @staticmethod
    def _get_color_codes(behavior_class: str) -> str:
        if behavior_class == 'crypto':
            return TagColor.RED
        if behavior_class == 'file_system':
            return TagColor.BLUE
        if behavior_class == 'network':
            return TagColor.ORANGE
        if behavior_class == 'memory_operations':
            return TagColor.GREEN
        if behavior_class == 'randomize':
            return TagColor.LIGHT_BLUE
        return TagColor.GRAY


def _get_behavior_classes(elf: lief.ELF) -> list[str]:
    libraries = _get_symbols_version_entries(normalize_lief_items(elf.symbols_version))
    libraries.extend(normalize_lief_items(elf.libraries))
    functions = _get_relevant_imp_functions(normalize_lief_items(elf.imported_functions))

    behaviour_classes = []
    for behaviour_class in BEHAVIOUR_CLASSES:
        indicators = BEHAVIOUR_CLASSES[behaviour_class]
        if _behaviour_class_applies(functions, libraries, indicators):
            behaviour_classes.append(behaviour_class)
    return behaviour_classes


def _get_relevant_imp_functions(imp_functions: list[str]) -> list[str]:
    return [f for f in imp_functions if not f.startswith('__')]


def _get_symbols_version_entries(symbol_versions: list[str]) -> list[str]:
    imported_libs = []
    for sv in symbol_versions:
        if str(sv) != '* Local *' and str(sv) != '* Global *':
            imported_libs.append(str(sv).split('(', maxsplit=1)[0])
    return list(set(imported_libs))


def _behaviour_class_applies(functions: list[str], libraries: list[str], indicators: list[str]) -> bool:
    for function in functions:
        for indicator in indicators:
            if (
                indicator.lower() in function.lower()
                and SequenceMatcher(None, indicator, function).ratio() >= FUNCTION_MATCHING_THRESHOLD
            ):
                return True
    for library in libraries:
        for indicator in indicators:
            if indicator.lower() in library.lower():
                return True
    return False


def _get_modinfo(elf: lief.ELF) -> list[str] | None:
    # getting the information from the *.ko files .modinfo section
    modinfo = None
    for section in elf.sections:
        if section.name == '.modinfo':
            modinfo = section.content.tobytes()
            modinfo = [entry.decode() for entry in modinfo.split(b'\x00') if entry]
            break
    return modinfo


def _convert_flags(json_dict: dict):
    # convert numerical flags to "human-readable" list of strings
    for section in json_dict['segments']:
        section['flags'] = _get_active_flags(section['flags'], ELF_SEGMENT_FLAGS)


def _get_active_flags(flags_value: int, flag_dict: dict[str, int]) -> list[str]:
    # get active flags from flags_value as list of strings
    return [flag_name for flag_name, flag_mask in flag_dict.items() if flags_value & flag_mask]


def _get_note_sections_content(elf: lief.ELF) -> Iterable[InfoSectionData]:
    for section in elf.sections:  # type: lief.ELF.Section
        if section.type == lief.ELF.SECTION_TYPES.NOTE:
            readable_content = bytes([c for c in section.content.tobytes() if c in PRINTABLE_BYTES])
            yield InfoSectionData(name=section.name, contents=readable_content.decode())
