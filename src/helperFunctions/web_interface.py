import json
import os
import re
from typing import List

from common_helper_files import get_binary_from_file
from passlib.context import CryptContext

from helperFunctions.fileSystem import get_template_dir
from helperFunctions.uid import is_uid

SPECIAL_CHARACTERS = 'ÄäÀàÁáÂâÃãÅåǍǎĄąĂăÆæĀāÇçĆćĈĉČčĎđĐďðÈèÉéÊêËëĚěĘęĖėĒēĜĝĢģĞğĤĥÌìÍíÎîÏïıĪīĮįĴĵĶķĹĺĻļŁłĽľÑñŃńŇňŅņÖöÒòÓóÔôÕõŐőØøŒœŔŕŘřẞßŚśŜŝŞşŠšȘș' \
                     'ŤťŢţÞþȚțÜüÙùÚúÛûŰűŨũŲųŮůŪūŴŵÝýŸÿŶŷŹźŽžŻż'


def get_color_list(number, limit=15):
    compliant_colors = ['#2b669a', '#cce0dc', '#2b669a', '#cce0dc', '#2b669a', '#cce0dc',
                        '#2b669a', '#cce0dc', '#2b669a', '#cce0dc', '#2b669a', '#cce0dc',
                        '#2b669a', '#cce0dc', '#2b669a', '#cce0dc', '#2b669a', '#cce0dc']
    return compliant_colors[:number if number <= limit else limit]


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


def virtual_path_element_to_span(hid_element: str, uid_element, root_uid) -> str:
    if is_uid(uid_element):
        return ('<span class="label label-primary"><a style="color: #fff" href="/analysis/{uid}/ro/{root_uid}">'
                '{hid}</a></span>'.format(uid=uid_element, root_uid=root_uid, hid=hid_element))
    return '<span class="label label-default">{}</span>'.format(hid_element)


def split_virtual_path(virtual_path: str) -> List[str]:
    return [element for element in virtual_path.split('|') if element]
