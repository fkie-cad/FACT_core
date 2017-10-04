import json
import os
from copy import deepcopy

from helperFunctions.dataConversion import unify_string_list
from helperFunctions.fileSystem import get_test_data_dir
from helperFunctions.yara_binary_search import YaraRuleError
from objects.file import FileObject
from objects.firmware import Firmware


def create_test_firmware(device_class="Router", device_name="test_router", vendor="test_vendor", bin_path="container/test.zip", all_files_included_set=False):
    fw = Firmware(file_path=os.path.join(get_test_data_dir(), bin_path))
    fw.set_device_class(device_class)
    fw.set_device_name(device_name)
    fw.set_vendor(vendor)
    fw.set_release_date("1970-01-01")
    fw.version = "0.1"
    processed_analysis = {'dummy': {'summary': ["sum a", "fw exclusive sum a"], 'content': "abcd"}}
    processed_analysis["unpacker"] = {"plugin_used": "used_unpack_plugin"}
    processed_analysis["file_type"] = {"mime": "test_type", "full": "Not a PE file"}
    fw.processed_analysis.update(processed_analysis)
    if all_files_included_set:
            fw.list_of_all_included_files = list(fw.files_included)
            fw.list_of_all_included_files.append(fw.get_uid())
    return fw


def create_test_file_object(bin_path="get_files_test/testfile1"):
    fo = FileObject(file_path=os.path.join(get_test_data_dir(), bin_path))
    processed_analysis = {'dummy': {'summary': ["sum a", "file exclusive sum b"], 'content': "file abcd"}, 'file_type': {'full': 'Not a PE file'}}
    fo.processed_analysis.update(processed_analysis)
    fo.virtual_file_path = fo.get_virtual_file_paths()
    return fo

TEST_FW = create_test_firmware(device_class="test class", device_name="test device", vendor="test vendor")
TEST_TEXT_FILE = create_test_file_object()


class DatabaseMock:
    fw_uid = TEST_FW.get_uid()
    fo_uid = TEST_TEXT_FILE.get_uid()

    def __init__(self, config=None):
        self.tasks = []

    def shutdown(self):
        pass

    def update_view(self, file_name, content):
        pass

    def get_meta_list(self, firmware_list=[]):
        fw_entry = ("test_uid", "test firmware", "unpacker")
        fo_entry = ("test_fo_uid", "test file object", "unpacker")
        if self.fw_uid in firmware_list and self.fo_uid in firmware_list:
            return [fw_entry, fo_entry]
        elif self.fo_uid in firmware_list:
            return [fo_entry]
        return [fw_entry]

    def get_object(self, uid, analysis_filter=[]):
        if uid == TEST_FW.get_uid():
            result = deepcopy(TEST_FW)
            result.processed_analysis = {
                "file_type": {"mime": "application/octet-stream", "full": "test text"},
                "mandatory_plugin": "mandatory result",
                "optional_plugin": "optional result"}
            return result
        elif uid == TEST_TEXT_FILE.get_uid():
            result = deepcopy(TEST_TEXT_FILE)
            result.processed_analysis = {
                "file_type": {"mime": "text/plain", "full": "plain text"}
            }
            return result
        else:
            return None

    def get_hid(self, uid, root_uid=None):
        return "TEST_FW_HID"

    def get_device_class_list(self):
        return ['test class']

    def get_vendor_list(self):
        return ['test vendor']

    def get_device_name_dict(self):
        return {'test class': {'test vendor': ['test device']}}

    def compare_result_is_in_db(self, uid_list):
        if uid_list == "valid_uid_list_in_db":
            return True
        elif uid_list == unify_string_list(';'.join([TEST_FW.uid, TEST_TEXT_FILE.uid])):
            return True
        else:
            return False

    def get_compare_result(self, compare_id):
        if compare_id == "valid_uid_list_not_in_db":
            return None
        elif compare_id == unify_string_list(';'.join([TEST_FW.uid, TEST_TEXT_FILE.uid])):
            return {'this_is': 'a_compare_result'}
        else:
            return "generic error"

    def existence_quick_check(self, uid):
        if uid == self.fw_uid or uid == self.fo_uid:
            return True
        elif uid == 'error':
            return True
        else:
            return False

    def object_existence_quick_check(self, compare_id):
        if compare_id == "valid_uid_list_not_in_db" or compare_id == "valid_uid_list_in_db":
            return None
        elif compare_id == unify_string_list(';'.join([TEST_TEXT_FILE.uid, TEST_FW.uid])):
            return None
        else:
            return "bla"

    def all_uids_found_in_database(self, uid_list):
        return True

    def add_comment_to_object(self, uid, comment, author, time):
        TEST_FW.comments.append(
            {"time": str(time), "author": author, "comment": comment}
        )

    class firmwares():
        @staticmethod
        def find_one(uid):
            if uid == "test_uid":
                return "test"
            elif uid == TEST_FW.get_uid():
                return TEST_FW.get_uid()
            else:
                return None

        @staticmethod
        def find(query, filter):
            return {}

    class file_objects():
        @staticmethod
        def find_one(uid):
            if uid == TEST_TEXT_FILE.get_uid():
                return TEST_TEXT_FILE.get_uid()
            else:
                return None

        @staticmethod
        def find(query, filter):
            return {}

    def get_data_for_nice_list(self, input_data, root_uid):
        return []

    @staticmethod
    def create_analysis_structure():
        return ""

    def generic_search(self, search_string, skip=0, limit=0, only_fo_parent_firmware=False):
        result = []
        if type(search_string) == dict:
            search_string = json.dumps(search_string)
        if self.fw_uid in search_string or search_string == "{}":
            result.append(self.fw_uid)
        if self.fo_uid in search_string or search_string == "{}":
            if not only_fo_parent_firmware:
                result.append(self.fo_uid)
            else:
                if self.fw_uid not in result:
                    result.append(self.fw_uid)
        return result

    def get_number_of_total_matches(self, query, firmware_only):
        if self.fw_uid in query and self.fo_uid in query:
            return 1 if firmware_only else 2
        elif self.fw_uid in query or self.fo_uid in query:
            return 1
        elif query == "{}":
            return 2
        else:
            return 0

    def add_analysis_task(self, task):
        self.tasks.append(task)

    def add_re_analyze_task(self, task):
        self.tasks.append(task)

    def add_compare_task(self, task, force=None):
        self.tasks.append((task, force))

    def get_available_analysis_plugins(self):
        return {
            "default_plugin": ("default plugin description", False, True),
            "mandatory_plugin": ("mandatory plugin description", True, False),
            "optional_plugin": ("optional plugin description", False, False),
            "file_type": ("file_type plugin", False, False)}

    def get_binary_and_filename(self, uid):
        if uid == TEST_FW.get_uid():
            return TEST_FW.binary, TEST_FW.file_name
        elif uid == TEST_TEXT_FILE.get_uid():
            return TEST_TEXT_FILE.binary, TEST_TEXT_FILE.file_name
        else:
            return None

    def get_repacked_binary_and_file_name(self, uid):
        if uid == TEST_FW.get_uid():
            return TEST_FW.binary, TEST_FW.file_name
        else:
            return None

    def add_binary_search_request(self, yara_rule_binary):
        if yara_rule_binary == b"invalid_rule":
            return YaraRuleError("error: invalid rule")
        else:
            return "some_id"

    def get_binary_search_result(self, uid):
        if uid == "some_id":
            return {"test_rule": ["test_uid"]}, b"some yara rule"
        else:
            return None, None

    def get_statistic(self, identifier):
        statistics = {
            'number_of_firmwares': 1,
            'number_of_unique_files': 0,
            'total_firmware_size': 10,
            'total_file_size': 20,
            'average_firmware_size': 10,
            'average_file_size': 20
        }
        if identifier == 'general':
            return statistics
        else:
            return None

    def get_complete_object_including_all_summaries(self, uid):
        if uid == TEST_FW.uid:
            return TEST_FW
        else:
            raise Exception("UID not found: {}".format(uid))

    def rest_get_firmware_uids(self, offset, limit, query=None):
        if (offset != 0) or (limit != 0):
            return []
        else:
            return [TEST_FW.uid, ]

    def rest_get_file_object_uids(self, offset, limit, query=None):
        if (offset != 0) or (limit != 0):
            return []
        else:
            return [TEST_TEXT_FILE.uid, ]

    def get_firmware(self, uid):
        if uid == TEST_FW.uid:
            return TEST_FW
        else:
            return None

    def get_file_object(self, uid):
        if uid == TEST_TEXT_FILE.uid:
            return TEST_TEXT_FILE
        else:
            return None

    def search_cve_summaries_for(self, keyword):
        return [{'_id': 'CVE-2012-0002'}]


def fake_exit(self, *args):
    pass
