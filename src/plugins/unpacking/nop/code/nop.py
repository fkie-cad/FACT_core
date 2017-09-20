'''
This plugin does not unpack any files files.
'''

name = 'NOP'
mime_patterns = ['generic/nop', 'inode/symlink']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    """
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    Optional: Return a dict with meta information
    """
    return {'info': 'unpacking skipped'}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))
