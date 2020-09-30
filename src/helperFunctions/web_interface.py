import json
import os
import re
from datetime import timedelta

from common_helper_files import get_binary_from_file
from matplotlib import cm, colors
from passlib.context import CryptContext
from si_prefix import si_format

from helperFunctions.fileSystem import get_template_dir
from helperFunctions.uid import is_uid

SPECIAL_CHARACTERS = (
    'ÄäÀàÁáÂâÃãÅåǍǎĄąĂăÆæĀāÇçĆćĈĉČčĎđĐďðÈèÉéÊêËëĚěĘęĖėĒē'
    'ĜĝĢģĞğĤĥÌìÍíÎîÏïıĪīĮįĴĵĶķĹĺĻļŁłĽľÑñŃńŇňŅņÖöÒòÓóÔôÕõŐőØøŒœ'
    'ŔŕŘřẞßŚśŜŝŞşŠšȘșŤťŢţÞþȚțÜüÙùÚúÛûŰűŨũŲųŮůŪūŴŵÝýŸÿŶŷŹźŽžŻż'
)


def get_color_list(number, limit=10):
    color_map = cm.get_cmap('rainbow')
    color_list = [colors.rgb2hex(color_map(i)) for i in range(32, 256, 22)]
    return color_list[:min(number, limit)]


def get_alternating_color_list(number, limit=10):
    color_list = get_color_list(8)
    # color_list[0] is blue, color_list[7] is yellow
    alternating_color_list = [color_list[0], color_list[7]] * (limit // 2 + 1)
    return alternating_color_list[:min(number, limit)]


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
    radare2_host = config['ExpertSettings']['radare2_host']
    if config.getboolean('ExpertSettings', 'nginx'):
        return 'https://{}/radare'.format(radare2_host)
    return 'http://{}:8000'.format(radare2_host)


def password_is_legal(pw: str) -> bool:
    if not pw:
        return False
    schemes = ['bcrypt', 'des_crypt', 'pbkdf2_sha256', 'pbkdf2_sha512', 'sha256_crypt', 'sha512_crypt', 'plaintext']
    ctx = CryptContext(schemes=schemes)
    return ctx.identify(pw) == 'plaintext'


def virtual_path_element_to_span(hid_element: str, uid_element, root_uid) -> str:
    if is_uid(uid_element):
        return (
            '<span class="badge badge-primary">'
            '    <a style="color: #fff" href="/analysis/{uid}/ro/{root_uid}">'
            '        {hid}'
            '    </a>'
            '</span>'.format(uid=uid_element, root_uid=root_uid, hid=cap_length_of_element(hid_element))
        )
    return '<span class="badge badge-secondary">{}</span>'.format(cap_length_of_element(hid_element))


def cap_length_of_element(hid_element, maximum=55):
    return '~{}'.format(hid_element[-(maximum - 1):]) if len(hid_element) > maximum else hid_element


def format_si_prefix(number: float, unit: str) -> str:
    return '{number}{unit}'.format(number=si_format(number, precision=2), unit=unit)


def format_time(seconds: float):
    if seconds < 60:
        return format_si_prefix(seconds, 's')
    return str(timedelta(seconds=seconds))
