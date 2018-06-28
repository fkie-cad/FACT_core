from pathlib import Path
from common_helper_process import execute_shell_command

name = 'ELF'
mime_patterns = ['application/x-executable']
unpacker_program = '7z'
version = '0.1'


def unpack_function(file_path, tmp_dir):
    meta = {}

    execution_string = 'fakeroot {} x -y -o{} {}'.format(unpacker_program, tmp_dir, file_path)
    output = execute_shell_command(execution_string)

    extraction_dir = Path(tmp_dir)
    normal_executable = False
    for child_path in extraction_dir.iterdir():
        if child_path.name == '.data':
            normal_executable = True
            break

    if normal_executable:
        clean_directory(extraction_dir)
        meta['output'] = 'Normal ELF file.\nWill not be extracted.\n\nPlease report if it\'s a self extracting archive'
    else:
        meta['output'] = output
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
