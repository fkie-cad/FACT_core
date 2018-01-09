import os
import re
import logging
import sys

from tempfile import TemporaryDirectory

from helperFunctions.uid import create_uid
from objects.firmware import Firmware


def create_analysis_task(request):
    task = _get_meta_from_request(request)
    if request.files['file']:
        task['file_name'], task['binary'] = get_file_name_and_binary_from_request(request)
    task['uid'] = get_uid_of_analysis_task(task)
    if task["release_date"] == '':
        # set default value if date field is empty
        task["release_date"] = "1970-01-01"
    return task


def get_file_name_and_binary_from_request(request):
    result = []
    try:
        result.append(request.files['file'].filename)
    except Exception:
        result.append("no name")
    result.append(get_uploaded_file_binary(request.files['file']))
    return result


def create_re_analyze_task(request, uid):
    task = _get_meta_from_request(request)
    task['uid'] = uid
    if not task["release_date"]:
        task["release_date"] = "1970-01-01"
    return task


def _get_meta_from_request(request):
    meta = {}
    meta['device_name'] = request.form['device_name']
    meta['device_class'] = request.form['device_class']
    meta['vendor'] = request.form['vendor']
    meta['firmware_version'] = request.form['firmware_version']
    meta['release_date'] = request.form['release_date']
    meta['requested_analysis_systems'] = request.form.getlist("analysis_systems")
    meta['tags'] = request.form['tags']
    meta = _get_meta_from_dropdowns(meta, request)
    if 'file_name' in request.form.keys():
        meta['file_name'] = request.form['file_name']
    return meta


def _get_meta_from_dropdowns(meta, request):
    for item in meta.keys():
        if not meta[item] and item not in ['firmware_version', 'release_date', 'requested_analysis_systems']:
            dd = request.form['{}_dropdown'.format(item)]
            if dd != "new entry":
                meta[item] = dd
    return meta


def _get_tag_list(tag_string):
    return tag_string.split(',')


def convert_analysis_task_to_fw_obj(analysis_task):
    fw = Firmware(scheduled_analysis=analysis_task['requested_analysis_systems'])
    if 'binary' in analysis_task.keys():
        fw.set_binary(analysis_task['binary'])
        fw.file_name = analysis_task['file_name']
    else:
        if 'file_name' in analysis_task.keys():
            fw.file_name = analysis_task['file_name']
        fw.overwrite_uid(analysis_task['uid'])
    fw.set_device_name(analysis_task['device_name'])
    fw.set_firmware_version(analysis_task['firmware_version'])
    fw.set_device_class(analysis_task['device_class'])
    fw.set_vendor(analysis_task['vendor'])
    fw.set_release_date(analysis_task['release_date'])
    for tag in _get_tag_list(analysis_task['tags']):
        fw.set_tag(tag)
    return fw


def convert_fw_obj_to_analysis_task(fw):
    analysis_task = {'binary': fw.binary,
                     'file_name': fw.file_name,
                     'device_name': fw.device_name,
                     'device_class': fw.device_class,
                     'vendor': fw.vendor,
                     'firmware_version': fw.version,
                     'release_date': fw.release_date,
                     'requested_analysis_systems': fw.scheduled_analysis,
                     'tags': ','.join(fw.tags),
                     'uid': fw.get_uid()}
    return analysis_task


def get_uid_of_analysis_task(analysis_task):
    if analysis_task['binary']:
        uid = create_uid(analysis_task['binary'])
        return uid
    else:
        return None


def get_uploaded_file_binary(request_file):
    if request_file:
        tmp_dir = TemporaryDirectory(prefix="faf_upload_")
        tmp_file_path = os.path.join(tmp_dir.name, "upload.bin")
        try:
            request_file.save(tmp_file_path)
            with open(tmp_file_path, 'rb') as f:
                binary = f.read()
            tmp_dir.cleanup()
            return binary
        except Exception:
            return None
    else:
        return None


def check_for_errors(analysis_task):
    error = {}
    for key in analysis_task:
        if analysis_task[key] in [None, "", b'']:
            error.update({key: "Please specify the {}".format(" ".join(key.split("_")))})
    return error


def is_sanitized_entry(entry):
    try:
        if re.search(r"_[0-9a-f]{64}_[0-9]+", entry) is None:
            return False
        else:
            return True
    except TypeError:  # DB entry has type other than string (e.g. integer or float)
        return False
    except Exception as e:
        logging.error("Could not determine entry sanitization state: {} {}".format(sys.exc_info()[0].__name__, e))
        return False
