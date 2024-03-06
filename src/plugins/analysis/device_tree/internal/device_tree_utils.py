from __future__ import annotations

import logging
from subprocess import run
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def int_from_buf(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 4], byteorder='big')


class Property:
    def __init__(self, raw: bytes, strings_by_offset: dict[int, bytes]):
        # a property consists of a struct {uint32_t len; uint32_t nameoff;} followed by the value
        # nameoff is an offset of the string in the strings block
        # see also: https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html#lexical-structure
        self.length = int_from_buf(raw, 4)
        self.name_offset = int_from_buf(raw, 8)
        self.name = strings_by_offset.get(self.name_offset, None)
        self.value = raw[12 : 12 + self.length].strip(b'\0')

    def get_size(self):
        return self.length + 12  # len(FDT_PROP + uint32_t len + uint32_t nameoff) == 12


class StructureBlock:
    FDT_PROP = b'\0\0\0\3'

    def __init__(self, raw: bytes, strings_by_offset: dict[int, bytes]):
        self.raw = raw
        self.strings_by_offset = strings_by_offset

    def __iter__(self):
        while True:
            next_property_offset = self.raw.find(self.FDT_PROP)
            if next_property_offset == -1:
                break
            prop = Property(self.raw[next_property_offset:], self.strings_by_offset)
            yield prop
            self.raw = self.raw[next_property_offset + prop.get_size() :]


def convert_device_tree_to_str(file_path: str | Path) -> str | None:
    process = run(f'dtc -I dtb -O dts {file_path}', shell=True, capture_output=True, check=False)
    if process.returncode != 0:
        logging.warning(
            f'The Device Tree Compiler exited with non-zero return code {process.returncode}: {process.stderr}'
        )
        return None
    return process.stdout.decode(errors='replace').strip()


def get_model_or_description(structure_block: StructureBlock):
    model, description = None, None
    for prop in structure_block:
        if prop.name == b'model':
            model = prop.value.decode(errors='replace')
        if not description and prop.name == b'description':
            description = prop.value.decode(errors='replace')
    return description, model
