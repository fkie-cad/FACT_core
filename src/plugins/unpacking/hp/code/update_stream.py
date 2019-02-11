from common_helper_extraction import (
    cut_at_padding, dump_files, extract_lzma_streams,
    get_decompressed_lzma_streams
)
from common_helper_files import get_binary_from_file

name = 'HP-Stream'
mime_patterns = ['firmware/hp-us']
version = '0.1'


def unpack_function(file_path: str, tmp_dir: str) -> dict:
    """
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    Optional: Return a dict with meta information
    """
    raw_binary = get_binary_from_file(file_path)
    data_sections = cut_at_padding(raw_binary, padding_min_length=16)
    lzma_streams = extract_lzma_streams(raw_binary)
    decompressed_lzma_streams = get_decompressed_lzma_streams(lzma_streams)

    dump_files(data_sections, tmp_dir)
    dump_files(decompressed_lzma_streams, tmp_dir, suffix='_lzma_decompressed')
    return _get_meta_data(data_sections, lzma_streams)


def _get_meta_data(data_sections: list, lzma_streams: list) -> dict:
    meta_data = {
        'number_of_zero_padded_sections': len(data_sections),
        'number_of_lzma_streams': len(lzma_streams),
    }
    return meta_data


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))
