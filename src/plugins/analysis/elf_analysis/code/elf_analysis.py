from __future__ import annotations

import json
import string
from difflib import SequenceMatcher
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional

import lief
from pydantic import BaseModel, Field
from semver import Version

from analysis.plugin import AnalysisPluginV0, Tag
from helperFunctions.tag import TagColor

FUNCTION_MATCHING_THRESHOLD = 0.85

if TYPE_CHECKING:
    from io import FileIO

TEMPLATE_FILE_PATH = Path(__file__).parent.parent / 'internal/matching_template.json'
BEHAVIOUR_CLASSES = json.loads(TEMPLATE_FILE_PATH.read_text())
PRINTABLE_BYTES = set(string.printable.encode())
ELF_SEGMENT_FLAGS = {
    0x1: 'execute',
    0x2: 'write',
    0x4: 'read',
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
    numberof_segments: int
    object_file_version: str
    processor_flag: int
    program_header_size: int
    program_headers_offset: int
    section_header_size: int
    section_headers_offset: int
    section_name_table_idx: int

    @classmethod
    def from_lief_header(cls, header: lief.ELF.Header) -> ElfHeader:
        return cls(
            entrypoint=header.entrypoint,
            file_type=header.file_type.__name__,
            header_size=header.header_size,
            identity_abi_version=header.identity_abi_version,
            identity_class=header.identity_class.__name__,
            identity_data=header.identity_data.__name__,
            identity_os_abi=header.identity_os_abi.__name__,
            identity_version=header.identity_version.__name__,
            machine_type=header.machine_type.__name__.lower(),
            numberof_sections=header.numberof_sections,
            numberof_segments=header.numberof_segments,
            object_file_version=header.object_file_version.__name__,
            processor_flag=header.processor_flag,
            program_header_size=header.program_header_size,
            program_headers_offset=header.program_header_offset,
            section_header_size=header.section_header_size,
            section_headers_offset=header.section_header_offset,
            section_name_table_idx=header.section_name_table_idx,
        )


class ElfSection(BaseModel):
    flags: List[str]
    name: str
    size: int
    type: str
    offset: int
    virtual_address: int

    @classmethod
    def from_lief_section(cls, section: lief.ELF.Section) -> ElfSection:
        return cls(
            flags=[f.__name__ for f in section.flags_list],
            name=section.name,
            size=section.size,
            type=section.type.__name__,
            offset=section.offset,
            virtual_address=section.virtual_address,
        )


class ElfSegment(BaseModel):
    file_offset: int
    flags: List[str]
    physical_address: int
    physical_size: int
    type: str
    virtual_address: int
    virtual_size: int

    @classmethod
    def from_lief_segment(cls, segment: lief.ELF.Segment) -> ElfSegment:
        return cls(
            file_offset=segment.file_offset,
            flags=[ELF_SEGMENT_FLAGS.get(segment.flags.value, 'None')],
            physical_address=segment.physical_address,
            physical_size=segment.physical_size,
            type=segment.type.__name__,
            virtual_address=segment.virtual_address,
            virtual_size=segment.virtual_size,
        )


class DynamicEntry(BaseModel):
    tag: str
    value: int
    library: Optional[str] = None
    flags: Optional[List[str]] = None
    array: Optional[List[str]] = None

    @classmethod
    def from_lief_dyn_entry(cls, entry: lief.ELF.DynamicEntry) -> DynamicEntry:
        return cls(
            tag=entry.tag.__name__,
            value=entry.value,
            library=getattr(entry, 'name', None),
            flags=[f.__name__ for f in entry.flags] if hasattr(entry, 'flags') else None,
            array=[str(i) for i in entry.array] if hasattr(entry, 'array') else None,
        )


class ElfSymbol(BaseModel):
    name: str
    offset: int


class InfoSectionData(BaseModel):
    name: str
    contents: str


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        header: ElfHeader
        sections: List[ElfSection]
        segments: List[ElfSegment]
        dynamic_entries: List[DynamicEntry]
        exported_functions: List[ElfSymbol]
        imported_functions: List[ElfSymbol]
        libraries: List[str]
        mod_info: Optional[Dict[str, str]] = Field(description='Key value pairs with Linux kernel module information.')
        note_sections: List[InfoSectionData]
        behavior_classes: List[str] = Field(description='List of behavior classes (e.g. "crypto" or "network").')

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
        elf = lief.ELF.parse(file_handle.name)
        if elf is None:
            raise ValueError('not a valid ELF file')
        return self.Schema(
            header=ElfHeader.from_lief_header(elf.header),
            exported_functions=[
                ElfSymbol(name=name, offset=address) for address, name in _deduplicate_functions(elf.exported_functions)
            ],
            imported_functions=[
                ElfSymbol(name=name, offset=address) for address, name in _deduplicate_functions(elf.imported_functions)
            ],
            sections=[ElfSection.from_lief_section(s) for s in elf.sections],
            segments=[ElfSegment.from_lief_segment(s) for s in elf.segments],
            dynamic_entries=[DynamicEntry.from_lief_dyn_entry(e) for e in elf.dynamic_entries],
            libraries=elf.libraries,
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
    libraries = _get_symbols_version_entries([str(s) for s in elf.symbols_version])
    libraries.extend([str(lib) for lib in elf.libraries])
    functions = _get_relevant_imp_functions([str(f) for f in elf.imported_functions])

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


def _get_modinfo(elf: lief.ELF) -> dict[str, str] | None:
    # getting the information from the *.ko files .modinfo section
    for section in elf.sections:
        if section.name == '.modinfo':
            return dict(
                tuple(entry.decode(errors='replace').split('=', maxsplit=1))
                for entry in section.content.tobytes().split(b'\x00')
                if entry and b'=' in entry
            )
    return None


def _get_note_sections_content(elf: lief.ELF) -> Iterable[InfoSectionData]:
    for section in elf.sections:  # type: lief.ELF.Section
        if section.type == lief.ELF.Section.TYPE.NOTE:
            readable_content = bytes([c for c in section.content.tobytes() if c in PRINTABLE_BYTES])
            yield InfoSectionData(name=section.name, contents=readable_content.decode())


def _deduplicate_functions(lief_functions: Iterable[lief.Function]) -> list[tuple[int, str]]:
    return sorted({(f.address, f.name) for f in lief_functions})
