import json
import os
import re

from common_helper_files import get_binary_from_file

from helperFunctions.fileSystem import get_template_dir
from passlib.context import CryptContext


SPECIAL_CHARACTERS = 'ÄäÀàÁáÂâÃãÅåǍǎĄąĂăÆæĀāÇçĆćĈĉČčĎđĐďðÈèÉéÊêËëĚěĘęĖėĒēĜĝĢģĞğĤĥÌìÍíÎîÏïıĪīĮįĴĵĶķĹĺĻļŁłĽľÑñŃńŇňŅņÖöÒòÓóÔôÕõŐőØøŒœŔŕŘřẞßŚśŜŝŞşŠšȘș' \
                     'ŤťŢţÞþȚțÜüÙùÚúÛûŰűŨũŲųŮůŪūŴŵÝýŸÿŶŷŹźŽžŻż'


def get_color_list(n, limit=15):
    compliant_colors = ['#2b669a', '#cce0dc', '#2b669a', '#cce0dc', '#2b669a', '#cce0dc',
                        '#2b669a', '#cce0dc', '#2b669a', '#cce0dc', '#2b669a', '#cce0dc',
                        '#2b669a', '#cce0dc', '#2b669a', '#cce0dc', '#2b669a', '#cce0dc']
    return compliant_colors[:n if n <= limit else limit]


def overwrite_default_plugins(intercom, checked_plugin_list):
    result = intercom.get_available_analysis_plugins()
    for item in result.keys():
        tmp = list(result[item])
        if item in checked_plugin_list:
            tmp[2] = True
        else:
            tmp[2] = False
        result[item] = tuple(tmp)
    return result


def apply_filters_to_query(request, query):
    query_dict = json.loads(query)
    for key in ['device_class', 'vendor']:
        if request.args.get(key):
            if key not in query_dict.keys():
                query_dict[key] = request.args.get(key)
            else:  # key was in the previous search query
                query_dict['$and'] = [{key: query_dict[key]}, {key: request.args.get(key)}]
                query_dict.pop(key)
    return query_dict


def filter_out_illegal_characters(string):
    if string is None:
        return string
    return re.sub('[^\\w {}!.-]'.format(SPECIAL_CHARACTERS), '', string)


class ConnectTo:
    def __init__(self, connected_interface, config):
        self.interface = connected_interface
        self.config = config

    def __enter__(self):
        self.connection = self.interface(self.config)
        return self.connection

    def __exit__(self, *args):
        self.connection.shutdown()


def get_template_as_string(view_name):
    path = os.path.join(get_template_dir(), view_name)
    return get_binary_from_file(path).decode('utf-8')


def get_radare_endpoint(config):
    if config.getboolean('ExpertSettings', 'nginx'):
        return 'https://localhost/radare'
    return 'http://localhost:8000'


def password_is_legal(pw: str) -> bool:
    if not pw:
        return False
    schemes = ['bcrypt', 'des_crypt', 'pbkdf2_sha256', 'pbkdf2_sha512', 'sha256_crypt', 'sha512_crypt', 'plaintext']
    ctx = CryptContext(schemes=schemes)
    return ctx.identify(pw) == 'plaintext'
