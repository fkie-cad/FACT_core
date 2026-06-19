from __future__ import annotations

from typing import TYPE_CHECKING, Any

from markupsafe import escape

from helperFunctions.uid import create_uid
from objects.firmware import Firmware

if TYPE_CHECKING:
    from flask import Request

OPTIONAL_FIELDS = ['tags', 'device_part']
DROPDOWN_FIELDS = ['device_class', 'vendor', 'device_name', 'device_part']


def create_analysis_task(request: Request) -> dict[str, Any]:
    """
    Create an analysis task from the data stored in the flask request object.

    :param request: The flask request object.
    :return: A dict containing the analysis task data.
    """
    task = _get_meta_from_request(request)
    if request.files['file']:
        task['file_name'], task['binary'] = get_file_name_and_binary_from_request(request)
    task['uid'] = _get_uid_of_analysis_task(task)
    if task['release_date'] == '':
        # set default value if date field is empty
        task['release_date'] = '1970-01-01'
    return task


def get_file_name_and_binary_from_request(request: Request) -> tuple[str, bytes]:
    """
    Retrieves the file name and content from the flask request object.

    :param request: The flask request object.
    :return: A Tuple containing the file name and the file content.
    """
    try:
        file_name: str = escape(request.files['file'].filename)
    except AttributeError:
        file_name = 'no name'
    file_binary = request.files['file'].read() if request.files['file'] else None
    return file_name, file_binary


def create_re_analyze_task(request: Request, uid: str) -> dict[str, Any]:
    """
    Create an analysis task for a file that is already in the database.

    :param request: The flask request object.
    :param uid: The unique identifier of the firmware.
    :return: A dict containing the analysis task data.
    """
    task = _get_meta_from_request(request)
    task['uid'] = uid
    if not task['release_date']:
        task['release_date'] = '1970-01-01'
    return task


def _get_meta_from_request(request: Request) -> dict[str, Any]:
    meta = {
        'device_name': escape(request.form['device_name']),
        'device_part': escape(request.form['device_part']),
        'device_class': escape(request.form['device_class']),
        'vendor': escape(request.form['vendor']),
        'version': escape(request.form['version']),
        'release_date': escape(request.form['release_date']),
        'requested_analysis_systems': request.form.getlist('analysis_systems'),
        'tags': escape(request.form['tags']),
    }
    _get_meta_from_dropdowns(meta, request)

    if 'file_name' in request.form:
        meta['file_name'] = escape(request.form['file_name'])
    return meta


def _get_meta_from_dropdowns(meta: dict, request: Request):
    for item in meta:
        if not meta[item] and item in DROPDOWN_FIELDS:
            dd = request.form[f'{item}_dropdown']
            if dd != 'new entry':
                meta[item] = escape(dd)


def _get_tag_list(tag_string: str | None) -> list[str]:
    if tag_string is None or tag_string == '':
        return []
    return tag_string.split(',')


def convert_analysis_task_to_fw_obj(analysis_task: dict, base_fw: Firmware | None = None) -> Firmware:
    """
    Convert an analysis task to a firmware object.

    :param analysis_task: The analysis task data.
    :param base_fw: The existing `Firmware` object in case of analysis update.
    :return: A `Firmware` object based on the analysis task data.
    """
    fw = base_fw or Firmware()
    fw.scheduled_analysis = analysis_task['requested_analysis_systems']
    if 'binary' in analysis_task:
        fw.set_binary(analysis_task['binary'])
        fw.file_name = analysis_task['file_name']
    else:
        if 'file_name' in analysis_task:
            fw.file_name = analysis_task['file_name']
        fw.uid = analysis_task['uid']
    fw.device_name = analysis_task['device_name']
    fw.set_part_name(analysis_task['device_part'])
    fw.version = analysis_task['version']
    fw.device_class = analysis_task['device_class']
    fw.vendor = analysis_task['vendor']
    fw.release_date = analysis_task['release_date']
    fw.tags = {}
    for tag in _get_tag_list(analysis_task['tags']):
        fw.set_tag(tag)
    return fw


def _get_uid_of_analysis_task(analysis_task: dict) -> str | None:
    """
    Creates a UID (unique identifier) for an analysis task. The UID is generated based on the binary stored in the
    analysis task dict. The return value may be `None` if no binary is contained in the analysis task dict.

    :param analysis_task: The analysis task data.
    :return: A UID based on the binary contained in the analysis task or `None` if there is no binary.
    """
    if analysis_task['binary']:
        return create_uid(analysis_task['binary'])
    return None
