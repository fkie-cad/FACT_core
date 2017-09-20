import json
import logging
import sys
from copy import deepcopy

from helperFunctions.compare_sets import remove_duplicates_from_list
from helperFunctions.dataConversion import get_value_of_first_key
from helperFunctions.database_structure import visualize_complete_tree
from helperFunctions.file_tree import get_partial_virtual_path, FileTreeNode
from helperFunctions.merge_generators import merge_generators, dict_to_sorted_tuples
from objects.file import FileObject
from storage.db_interface_common import MongoInterfaceCommon


class FrontEndDbInterface(MongoInterfaceCommon):

    READ_ONLY = True

    def get_meta_list(self, firmware_list=None):
        list_of_firmware_data = []
        if firmware_list is None:
            firmware_list = self.firmwares.find()
        for q in firmware_list:
            if q:
                if q["processed_analysis"]["unpacker"]["file_system_flag"]:
                    unpacker = self.retrieve_analysis(deepcopy(q["processed_analysis"]))["unpacker"]["plugin_used"]
                else:
                    unpacker = q["processed_analysis"]["unpacker"]["plugin_used"]
                list_of_firmware_data.append((q['_id'], self.get_hid(q['_id']), unpacker))
        return list_of_firmware_data

    def get_hid(self, uid, root_uid=None):
        """
        returns a human readable identifier (hid) for a given uid
        returns an empty string if uid is not in Database
        """
        hid = self._get_hid_firmware(uid)
        if hid is None:
            hid = self._get_hid_fo(uid, root_uid)
        if hid is None:
            return ""
        else:
            return hid

    def get_data_for_nice_list(self, uid_list, root_uid):
        query = self._build_search_query_for_uid_list(uid_list)
        result = self.generate_nice_list_data(merge_generators(self.firmwares.find(query), self.file_objects.find(query)), root_uid)
        return result

    @staticmethod
    def generate_nice_list_data(db_iterable, root_uid):
        result = []
        for db_entry in db_iterable:
            if db_entry is not None:
                result.append({
                    "uid": db_entry["_id"],
                    "files_included": db_entry["files_included"],
                    "size": db_entry["size"],
                    "mime-type": db_entry["processed_analysis"]["file_type"]["mime"],
                    "virtual_file_paths": db_entry["virtual_file_path"][root_uid] if root_uid in db_entry["virtual_file_path"] else get_value_of_first_key(db_entry["virtual_file_path"])
                })
        return result

    def get_file_name(self, uid):
        fo = self.get_object(uid)
        return fo.file_name

    def get_firmware_attribute_list(self, attribute, restrictions=None):
        attribute_list = set()
        query = self.firmwares.find(restrictions)
        for item in query:
            attribute_list.add(item[attribute])
        return list(attribute_list)

    def get_device_class_list(self):
        return self.get_firmware_attribute_list("device_class")

    def get_vendor_list(self):
        return self.get_firmware_attribute_list("vendor")

    def get_device_name_dict(self):
        device_name_dict = {}
        query = self.firmwares.find()
        for item in query:
            if item["device_class"] not in device_name_dict.keys():
                device_name_dict[item["device_class"]] = {item["vendor"]: [item["device_name"]]}
            else:
                if item["vendor"] not in device_name_dict[item["device_class"]].keys():
                    device_name_dict[item["device_class"]][item["vendor"]] = [item["device_name"]]
                else:
                    if item["device_name"] not in device_name_dict[item["device_class"]][item["vendor"]]:
                        device_name_dict[item["device_class"]][item["vendor"]].append(item["device_name"])
        return device_name_dict

    @staticmethod
    def _get_one_virtual_path_of_fo(fo_dict, root_uid):
        if root_uid is None or root_uid not in fo_dict['virtual_file_path'].keys():
            root_uid = list(fo_dict['virtual_file_path'].keys())[0]
        return FileObject.get_top_of_virtual_path(fo_dict['virtual_file_path'][root_uid][0])

    def _get_hid_firmware(self, uid):
        fw = self.firmwares.find_one({"_id": uid}, {'vendor': 1, 'device_name': 1, 'version': 1, 'device_class': 1})
        if fw is not None:
            return "{} {} - {} ({})".format(fw['vendor'], fw['device_name'], fw['version'], fw["device_class"])
        else:
            return None

    def _get_hid_fo(self, uid, root_uid):
        fo = self.file_objects.find_one({"_id": uid}, {'virtual_file_path': 1})
        if fo is not None:
            return self._get_one_virtual_path_of_fo(fo, root_uid)
        else:
            return None

    def all_uids_found_in_database(self, uid_list):
        if not uid_list:
            return True
        query = self._build_search_query_for_uid_list(uid_list)
        number_of_results = self.firmwares.find(query).count() + self.file_objects.find(query).count()
        return len(uid_list) == number_of_results

    def generic_search(self, search_dict, skip=0, limit=0, only_fo_parent_firmware=False):
        try:
            if type(search_dict) == str:
                search_dict = json.loads(search_dict)

            query = self.firmwares.find(search_dict, {'_id': 1}, skip=skip, limit=limit, sort=[('vendor', 1)])
            result = [match["_id"] for match in query]

            if len(result) < limit or limit == 0:
                max_firmware_results = self.get_firmware_number(query=search_dict)
                skip_fo = skip - max_firmware_results if skip > max_firmware_results else 0
                limit_fo = limit - len(result) if limit > 0 else 0
                if not only_fo_parent_firmware:
                    query = self.file_objects.find(search_dict, {'_id': 1}, skip=skip_fo, limit=limit_fo, sort=[('file_name', 1)])
                    result.extend([match["_id"] for match in query])
                else:  # only searching for parents of matching file objects
                    query = self.file_objects.find(search_dict, {"virtual_file_path": 1})
                    parent_uids = {uid for match in query for uid in match["virtual_file_path"].keys()}
                    query_filter = {"$nor": [{"_id": {"$nin": list(parent_uids)}}, search_dict]}
                    query = self.firmwares.find(query_filter, {'_id': 1}, skip=skip_fo, limit=limit_fo, sort=[('file_name', 1)])
                    parents = [match["_id"] for match in query]
                    result = remove_duplicates_from_list(result + parents)

        except Exception as e:
            error_message = "could not process search request: {} {}".format(sys.exc_info()[0].__name__, e)
            logging.warning(error_message)
            return error_message
        return result

    def get_specific_fields_of_db_entry(self, uid, field_dict):
        return self.file_objects.find_one(uid, field_dict) or self.firmwares.find_one(uid, field_dict)

    def get_specific_fields_for_multiple_entries(self, uid_list, field_dict):
        query = self._build_search_query_for_uid_list(uid_list)
        return self.file_objects.find(query, field_dict)

    @staticmethod
    def _convert_result_list_to_dict(search_results):
        return {entry["_id"]: entry for entry in search_results}

    # --- statistics

    def get_X_last_added_firmwares(self, limit_x=10):
        db_entries = self.firmwares.find({'submission_date': {"$gt": 1}}, {'_id': 1, 'vendor': 1, 'device_name': 1, 'version': 1, 'device_class': 1, 'submission_date': 1}, limit=limit_x, sort=[('submission_date', -1)])
        result = []
        for item in db_entries:
            result.append(item)
        return result

    def get_latest_comments(self, limit=10):
        comments = []
        for collection in [self.firmwares, self.file_objects]:
            db_entries = collection.aggregate([
                {"$match": {"comments": {"$not": {"$size": 0}}}},
                {"$project": {"_id": 1, "comments": 1}},
                {"$unwind": {"path": "$comments"}},
                {"$sort": {'comments.time': -1}},
                {"$limit": limit}
            ])
            comments.extend([
                {**entry["comments"], "uid": entry["_id"]}  # caution: >=python3.5 exclusive syntax
                for entry in db_entries if entry["comments"]
            ])
        comments.sort(key=lambda x: x["time"], reverse=True)
        return comments

    def get_number_of_firmwares_in_db(self):
        return self.firmwares.count()

    def get_file_type_statistics(self):
        file_type_dict = {}
        for fo in merge_generators(self.firmwares.find({}, {"processed_analysis.file_type.mime": 1, "virtual_file_path": 1}), self.file_objects.find({}, {"processed_analysis.file_type.mime": 1, "virtual_file_path": 1})):
            file_type = fo["processed_analysis"]["file_type"]["mime"]
            if file_type in file_type_dict:
                # one file can appear multiple times in the same firmware or in different firmwares
                file_type_dict[file_type] += len(fo["virtual_file_path"])
            else:
                file_type_dict[file_type] = len(fo["virtual_file_path"])
        return dict_to_sorted_tuples(file_type_dict)

    # --- file tree

    def _create_node_from_virtual_path(self, uid, root_uid, current_virtual_path, fo_data):
        if len(current_virtual_path) > 1:  # in the middle of a virtual file path
            node = FileTreeNode(uid=None, virtual=True, name=current_virtual_path.pop(0))
            for n in self.generate_file_tree_node(uid, root_uid, current_virtual_path=current_virtual_path, fo_data=fo_data):
                node.add_child_node(n)
        else:  # at the end of a virtual path aka a 'real' file
            has_children = fo_data["files_included"] != []
            node = FileTreeNode(uid, virtual=False, name=fo_data["file_name"], size=fo_data["size"],
                                mime_type=fo_data["processed_analysis"]["file_type"]["mime"], has_children=has_children)
        return node

    def generate_file_tree_node(self, uid, root_uid, current_virtual_path=None, fo_data=None):
        required_fields = {"virtual_file_path": 1, "files_included": 1, "file_name": 1, "size": 1, "processed_analysis.file_type.mime": 1, "_id": 1}
        if fo_data is None:
            fo_data = self.get_specific_fields_of_db_entry({"_id": uid}, required_fields)
        try:
            if root_uid not in fo_data["virtual_file_path"]:  # file tree for a file object (instead of a firmware)
                fo_data["virtual_file_path"] = get_partial_virtual_path(fo_data["virtual_file_path"], root_uid)
            if current_virtual_path is None:
                for entry in fo_data["virtual_file_path"][root_uid]:  # the same file may occur several times with different virtual paths
                    current_virtual_path = entry.split("/")[1:]
                    yield self._create_node_from_virtual_path(uid, root_uid, current_virtual_path, fo_data)
            else:
                yield self._create_node_from_virtual_path(uid, root_uid, current_virtual_path, fo_data)
        except Exception:  # the requested data is not present in the DB aka the file has not been analyzed yet
            yield FileTreeNode(uid=uid, not_analyzed=True, name="{} (not analyzed yet)".format(uid))

    def get_number_of_total_matches(self, query, only_parent_firmwares):
        if not only_parent_firmwares:
            return self.get_firmware_number(query=query) + self.get_file_object_number(query=query)
        else:
            if type(query) == str:
                query = json.loads(query)
            fw_matches = {match["_id"] for match in self.firmwares.find(query)}
            fo_matches = {parent for match in self.file_objects.find(query)
                          for parent in match["virtual_file_path"].keys()} if query != {} else set()
            return len(fw_matches.union(fo_matches))

    def create_analysis_structure(self):
        if self.client.varietyResults.file_objectsKeys.count() == 0:
            return "Database statistics do not seem to be created yet."

        file_object_keys = self.client.varietyResults.file_objectsKeys.find()
        all_field_strings = list(key_item['_id']['key'] for key_item in file_object_keys if
                                 key_item['_id']['key'].startswith('processed_analysis') and key_item['percentContaining'] >= float(self.config['data_storage']['structural_threshold']))
        stripped_field_strings = list(field[len("processed_analysis."):] for field in all_field_strings if field != "processed_analysis")

        return visualize_complete_tree(stripped_field_strings)

    def rest_get_firmware_uids(self, offset, limit, query=None):
        return self.rest_get_object_uids(self.firmwares, offset, limit, query if query else dict())

    def rest_get_file_objects_uids(self, offset, limit, query=None):
        return self.rest_get_object_uids(self.file_objects, offset, limit, query if query else dict())

    def rest_get_object_uids(self, database, offset, limit, query):
        uid_cursor = database.find(query, {'_id': 1}).skip(offset).limit(limit)
        return [result['_id'] for result in uid_cursor]
