from helperFunctions.fileSystem import get_src_dir


def get_config_dir():
    '''
    Returns the absolute path of the config directory
    '''
    return f'{get_src_dir()}/config'
