from pathlib import Path

from plugins.unpacking.sevenz.code.sevenz import unpack_function as sevenz

name = 'SFX'
mime_patterns = ['application/x-executable', 'application/x-dosexec']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    meta = sevenz(file_path, tmp_dir)

    extraction_dir = Path(tmp_dir)

    for child_path in extraction_dir.iterdir():
        if child_path.name in ['.text', '.data']:
            clean_directory(extraction_dir)
            meta['output'] = 'Normal executable files will not be extracted.' \
                             '\n\nPlease report if it\'s a self extracting archive'
            break

    return meta


def clean_directory(directory: Path):
    for child in directory.iterdir():
        if not child.is_dir():
            child.unlink()
        else:
            clean_directory(child)


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))
