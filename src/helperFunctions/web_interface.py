import json
import re
from datetime import timedelta
from typing import List, Optional

from common_helper_files import get_binary_from_file
from matplotlib import cm, colors
from passlib.context import CryptContext
from si_prefix import si_format

from helperFunctions.fileSystem import get_template_dir

SPECIAL_CHARACTERS = (
    'ÄäÀàÁáÂâÃãÅåǍǎĄąĂăÆæĀāÇçĆćĈĉČčĎđĐďðÈèÉéÊêËëĚěĘęĖėĒē'
    'ĜĝĢģĞğĤĥÌìÍíÎîÏïıĪīĮįĴĵĶķĹĺĻļŁłĽľÑñŃńŇňŅņÖöÒòÓóÔôÕõŐőØøŒœ'
    'ŔŕŘřẞßŚśŜŝŞşŠšȘșŤťŢţÞþȚțÜüÙùÚúÛûŰűŨũŲųŮůŪūŴŵÝýŸÿŶŷŹźŽžŻż'
)


def get_color_list(number: int, limit: int = 10) -> List[str]:
    '''
    Get a list of (different) color values as a hexadecimal string compatible to HTML (e.g. ``#00ff00`` for green).

    :param number: The number of colors in the returned list (with a cap of ``limit``).
    :param limit: The maximum number of returned colors.
    :return: A list of hex color values.
    '''
    color_map = cm.get_cmap('rainbow')
    color_list = [colors.rgb2hex(color_map(i)) for i in range(32, 256, (256 - 32) // limit)]
    return color_list[: min(number, limit)]


def get_alternating_color_list(number: int, limit: int = 10) -> List[str]:
    '''
    Get a list of alternating color values (beginning with blue and alternating with yellow) as a hexadecimal string
    compatible to HTML.

    :param number: The number of colors in the returned list (with a cap of ``limit``).
    :param limit: The maximum number of returned colors.
    :return: A list of alternating hex color values.
    '''
    color_list = get_color_list(8, limit=10)
    alternating_color_list = [color_list[0], color_list[7]] * (limit // 2 + 1)
    return alternating_color_list[: min(number, limit)]


def apply_filters_to_query(request, query: str) -> dict:
    '''
    Add a filter, selected in the web interface (vendor or device class), to the given query and return it.
    If the filter was already present in the query, it is updated.

    :param request: A given request (represented by the Flask object).
    :param query: A JSON MongoDB query.
    :return: The updated query.
    '''
    query_dict = json.loads(query)
    for key in ['device_class', 'vendor']:
        value = request.args.get(key)
        if value:
            query_dict.update({key: value})
    return query_dict


def filter_out_illegal_characters(string: Optional[str]) -> Optional[str]:
    '''
    Filter out any illegal characters from a given string.

    :param string: The string to be filtered.
    :return: The filtered string.
    '''
    if string is None:
        return string
    return re.sub(f'[^\\w {SPECIAL_CHARACTERS}!.-]', '', string)


def get_template_as_string(view_name: str) -> str:
    '''
    Get the content of template ``view_name`` from the template directory as string.

    :param view_name: The name of the template file.
    :return: The contents of the template file as string.
    '''
    template_path = get_template_dir() / view_name
    return get_binary_from_file(str(template_path)).decode('utf-8')


def password_is_legal(pw: str) -> bool:
    '''
    Check whether a given password is erroneously identified as an hashed password string (which might cause
    unexpected behavior).

    :param pw: The password string.
    :return: ``True`` if the password is accepted and ``False`` otherwise.
    '''
    if not pw:
        return False
    schemes = ['bcrypt', 'des_crypt', 'pbkdf2_sha256', 'pbkdf2_sha512', 'sha256_crypt', 'sha512_crypt', 'plaintext']
    ctx = CryptContext(schemes=schemes)
    return ctx.identify(pw) == 'plaintext'


def cap_length_of_element(hid_element: str, maximum: int = 55) -> str:
    '''
    Limit the length of an HID element of the "Virtual File Path", so that it can be displayed in the web interface
    without errors

    :param hid_element: An element of the virtual file path.
    :param maximum: The length after witch the element is capped.
    :return: The capped string.
    '''
    return f'~{hid_element[-(maximum - 1):]}' if len(hid_element) > maximum else hid_element


def _format_si_prefix(number: float, unit: str) -> str:
    return f'{si_format(number, precision=2)}{unit}'


def format_time(seconds: float) -> str:
    '''
    Format a duration value to be displayed in the web interface.

    :param seconds: The duration in seconds.
    :return: The formatted duration.
    '''
    if seconds < 60:
        return _format_si_prefix(seconds, 's')
    return str(timedelta(seconds=seconds))
