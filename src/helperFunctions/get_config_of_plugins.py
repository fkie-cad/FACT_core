from pathlib import Path
from helperFunctions.fileSystem import get_src_dir


def get_path_to_conf():
    return str(Path(get_src_dir()))+'/config/main.cfg'


def load_plugin_conf(input_list):
    path_to_config = get_path_to_conf()
    dict_of_plugins = input_list

    lines = []

    with open(path_to_config) as config_file:
        for line in config_file:
            lines.append(line)

    info = {}
    for i in range(len(lines)):
        if lines[i][0] == '[':
            for plugin_name in dict_of_plugins:
                if plugin_name in lines[i]:
                    j = i
                    while(j < len(lines)):
                        if 'threads' in lines[j]:
                            threads = lines[j].split('=')[1].rstrip()
                            info.update({plugin_name : threads})
                            break
                        j += 1
    return info