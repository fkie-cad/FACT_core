import logging
import struct
from pathlib import Path
from subprocess import PIPE, run
from tempfile import NamedTemporaryFile
from typing import List, NamedTuple, Optional, Union

from more_itertools import chunked

MAGIC = bytes.fromhex('D00DFEED')
MODEL_STR = b'model\0'

HEADER_SIZE = 40


def _bytes_to_int(byte_str: List[int]) -> int:
    return int.from_bytes(bytes(byte_str), byteorder='big')


def _int_to_bytes(number: int) -> bytes:
    return struct.pack('>I', number)


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


def parse_dtb_header(raw: bytes) -> DeviceTreeHeader:
    return DeviceTreeHeader(*[_bytes_to_int(chunk) for chunk in chunked(raw[4:HEADER_SIZE], 4)])


def find_model(raw: bytes, header: DeviceTreeHeader) -> Optional[str]:
    strings_block = raw[header.strings_block_offset:header.strings_block_offset + header.strings_block_size]
    structure_block = raw[header.struct_block_offset:header.struct_block_offset + header.struct_block_size]
    if MODEL_STR in strings_block:
        # the model name is stored in a "property" with preceding 4 byte length and "name offset" (in the string block)
        # => the model name will be where its string from the strings block is referenced
        # see also: https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html#lexical-structure
        model_str_offset = strings_block.find(MODEL_STR)
        model_str_address = _int_to_bytes(model_str_offset)
        if model_str_address in structure_block:
            entry_offset = structure_block.find(model_str_address) - 4
            entry_len = _bytes_to_int(structure_block[entry_offset:entry_offset + 4])
            return structure_block[entry_offset + 8:entry_offset + 8 + entry_len].strip(b'\0').decode(errors='replace')
    return None


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
    process = run(f'dtc -I dtb -O dts {file_path}', shell=True, stdout=PIPE, stderr=PIPE)  # pylint: disable=subprocess-run-check
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
    model = find_model(raw, header)
    device_tree = raw[:header.size]
    with NamedTemporaryFile(mode='wb') as temp_file:
        Path(temp_file.name).write_bytes(device_tree)
        string_representation = convert_device_tree_to_str(temp_file.name)
    if string_representation:
        return _result_to_json(header, string_representation, model)
    return None


def _result_to_json(header: DeviceTreeHeader, string_representation: str, model: Optional[str]) -> dict:
    return {
        'header': header._asdict(),
        'device_tree': string_representation,
        'model': model,
    }
