from common_helper_extraction import (
    cut_at_padding, dump_files, extract_lzma_streams,
    get_decompressed_lzma_streams
)
from common_helper_files import get_binary_from_file

name = 'RAW'
mime_patterns = ['data/raw']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    raw_binary = get_binary_from_file(file_path)
    ff_padded_sections = cut_at_padding(raw_binary, padding_min_length=16, padding_pattern=b'\xff')
    lzma_streams = extract_lzma_streams(raw_binary)
    decompressed_lzma_streams = get_decompressed_lzma_streams(lzma_streams)

    dump_files(ff_padded_sections, tmp_dir)
    dump_files(decompressed_lzma_streams, tmp_dir, suffix='_lzma_decompressed')
    return _get_meta_data(ff_padded_sections, lzma_streams)


def _get_meta_data(data_sections: list, lzma_streams: list) -> dict:
    meta_data = {
        'number_of_ff_padded_sections': len(data_sections),
        'number_of_lzma_streams': len(lzma_streams),
    }
    return meta_data


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))
