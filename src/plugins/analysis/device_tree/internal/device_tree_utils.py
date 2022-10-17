import logging
from pathlib import Path
from subprocess import run
from tempfile import NamedTemporaryFile
from typing import Dict, List, NamedTuple, Optional, Union

from more_itertools import chunked

MAGIC = bytes.fromhex('D00DFEED')

HEADER_SIZE = 40


def _bytes_to_int(byte_str: List[int]) -> int:
    return int.from_bytes(bytes(byte_str), byteorder='big')


class DeviceTreeHeader(NamedTuple):
    # Based on https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html#header
    size: int
    struct_block_offset: int
    strings_block_offset: int
    memory_map_offset: int
    version: int
    oldest_compatible_version: int
    boot_cpu_id: int
    strings_block_size: int
    struct_block_size: int


class Property:
    def __init__(self, raw: bytes, strings_by_offset: Dict[int, bytes]):
        # a property consists of a struct {uint32_t len; uint32_t nameoff;} followed by the value
        # nameoff is an offset of the string in the strings block
        # see also: https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html#lexical-structure
        self.length = _bytes_to_int(list(raw[4:8]))
        self.name_offset = _bytes_to_int(list(raw[8:12]))
        self.name = strings_by_offset.get(self.name_offset, None)
        self.value = raw[12:12 + self.length].strip(b'\0')

    def get_size(self):
        return self.length + 12  # len(FDT_PROP + uint32_t len + uint32_t nameoff) == 12


class StructureBlock:
    FDT_PROP = b'\0\0\0\3'

    def __init__(self, raw: bytes, strings_by_offset: Dict[int, bytes]):
        self.raw = raw
        self.strings_by_offset = strings_by_offset

    def __iter__(self):
        while True:
            next_property_offset = self.raw.find(self.FDT_PROP)
            if next_property_offset == -1:
                break
            prop = Property(self.raw[next_property_offset:], self.strings_by_offset)
            yield prop
            self.raw = self.raw[next_property_offset + prop.get_size():]


def parse_dtb_header(raw: bytes) -> DeviceTreeHeader:
    return DeviceTreeHeader(*[_bytes_to_int(chunk) for chunk in chunked(raw[4:HEADER_SIZE], 4)])


def header_has_illegal_values(header: DeviceTreeHeader, max_size: int) -> bool:
    values = [
        header.struct_block_offset,
        header.strings_block_offset,
        header.struct_block_size,
        header.strings_block_size
    ]
    return (
        header.version > 20
        or any(n > max_size or n > header.size for n in values)
        or header.size > max_size
    )


def convert_device_tree_to_str(file_path: Union[str, Path]) -> Optional[str]:
    process = run(f'dtc -I dtb -O dts {file_path}', shell=True, capture_output=True)  # pylint: disable=subprocess-run-check
    if process.returncode != 0:
        logging.warning(
            f'The Device Tree Compiler exited with non-zero return code {process.returncode}: {process.stderr}'
        )
        return None
    return process.stdout.decode(errors='replace').strip()


def dump_device_trees(raw: bytes) -> List[dict]:
    total_offset = 0
    dumped_device_trees = []

    while MAGIC in raw:
        offset = raw.find(MAGIC)
        raw = raw[offset:]
        total_offset += offset

        json_result = analyze_device_tree(raw)
        if json_result:
            json_result['offset'] = total_offset
            dumped_device_trees.append(json_result)

        # only skip HEADER_SIZE ahead because device trees might be inside other device trees
        raw = raw[HEADER_SIZE:]
        total_offset += HEADER_SIZE

    return dumped_device_trees


def analyze_device_tree(raw: bytes) -> Optional[dict]:
    header = parse_dtb_header(raw)
    if header_has_illegal_values(header, len(raw)):
        return None  # probably false positive

    device_tree = raw[:header.size]
    strings_block = device_tree[header.strings_block_offset:header.strings_block_offset + header.strings_block_size]
    structure_block = device_tree[header.struct_block_offset:header.struct_block_offset + header.struct_block_size]
    strings_by_offset = {strings_block.find(s): s for s in strings_block.split(b'\0') if s}
    description, model = _get_model_or_description(StructureBlock(structure_block, strings_by_offset))

    with NamedTemporaryFile(mode='wb') as temp_file:
        Path(temp_file.name).write_bytes(device_tree)
        string_representation = convert_device_tree_to_str(temp_file.name)
    if string_representation:
        return _result_to_json(header, string_representation, model, description)
    return None


def _get_model_or_description(structure_block: StructureBlock):
    model, description = None, None
    for prop in structure_block:
        if prop.name == b'model':
            model = prop.value.decode(errors='replace')
        if not description and prop.name == b'description':
            description = prop.value.decode(errors='replace')
    return description, model


def _result_to_json(header: DeviceTreeHeader, string_representation: str, model: Optional[str], description: Optional[str]) -> dict:
    return {
        'header': header._asdict(),
        'device_tree': string_representation,
        'model': model,
        'description': description,
    }
