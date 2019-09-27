import json
import logging
import sys
from copy import deepcopy

from helperFunctions.compare_sets import remove_duplicates_from_list
from helperFunctions.database_structure import visualize_complete_tree
from helperFunctions.dataConversion import get_value_of_first_key
from helperFunctions.file_tree import FileTreeNode, get_partial_virtual_path
from helperFunctions.merge_generators import merge_generators
from helperFunctions.tag import TagColor
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_common import MongoInterfaceCommon


class FrontEndDbInterface(MongoInterfaceCommon):

    READ_ONLY = True

    def get_meta_list(self, firmware_list=None):
        list_of_firmware_data = []
        if firmware_list is None:
            firmware_list = self.firmwares.find()
        for firmware in firmware_list:
            if firmware:
                tags = firmware['tags'] if 'tags' in firmware else dict()
                tags[self._get_unpacker_name(firmware)] = TagColor.LIGHT_BLUE
                submission_date = firmware['submission_date'] if 'submission_date' in firmware else 0
                list_of_firmware_data.append((firmware['_id'], self.get_hid(firmware['_id']), tags, submission_date))
        return list_of_firmware_data

    def _get_unpacker_name(self, firmware):
        if 'unpacker' not in firmware['processed_analysis']:
            return 'NOP'
        if firmware['processed_analysis']['unpacker']['file_system_flag']:
            return self.retrieve_analysis(deepcopy(firmware['processed_analysis']))['unpacker']['plugin_used']
        return firmware['processed_analysis']['unpacker']['plugin_used']

    def get_hid(self, uid, root_uid=None):
        '''
        returns a human readable identifier (hid) for a given uid
        returns an empty string if uid is not in Database
        '''
        hid = self._get_hid_firmware(uid)
        if hid is None:
            hid = self._get_hid_fo(uid, root_uid)
        if hid is None:
            return ''
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
                virtual_file_path = db_entry['virtual_file_path']
                result.append({
                    'uid': db_entry['_id'],
                    'files_included': db_entry['files_included'],
                    'size': db_entry['size'],
                    'mime-type': db_entry['processed_analysis']['file_type']['mime'] if 'file_type' in db_entry['processed_analysis'] else 'file-type-plugin/not-run-yet',
                    'virtual_file_paths': virtual_file_path[root_uid] if root_uid in virtual_file_path else get_value_of_first_key(virtual_file_path)
                })
        return result

    def get_file_name(self, uid):
        file_object = self.get_object(uid, analysis_filter=[])
        return file_object.file_name

    def get_firmware_attribute_list(self, attribute, restrictions=None):
        attribute_list = set()
        query = self.firmwares.find(restrictions)
        for item in query:
            attribute_list.add(item[attribute])
        return list(attribute_list)

    def get_device_class_list(self):
        return self.get_firmware_attribute_list('device_class')

    def get_vendor_list(self):
        return self.get_firmware_attribute_list('vendor')

    def get_device_name_dict(self):
        device_name_dict = {}
        query = self.firmwares.find()
        for item in query:
            if item['device_class'] not in device_name_dict.keys():
                device_name_dict[item['device_class']] = {item['vendor']: [item['device_name']]}
            else:
                if item['vendor'] not in device_name_dict[item['device_class']].keys():
                    device_name_dict[item['device_class']][item['vendor']] = [item['device_name']]
                else:
                    if item['device_name'] not in device_name_dict[item['device_class']][item['vendor']]:
                        device_name_dict[item['device_class']][item['vendor']].append(item['device_name'])
        return device_name_dict

    @staticmethod
    def _get_one_virtual_path_of_fo(fo_dict, root_uid):
        if root_uid is None or root_uid not in fo_dict['virtual_file_path'].keys():
            root_uid = list(fo_dict['virtual_file_path'].keys())[0]
        return FileObject.get_top_of_virtual_path(fo_dict['virtual_file_path'][root_uid][0])

    def _get_hid_firmware(self, uid):
        firmware = self.firmwares.find_one({'_id': uid}, {'vendor': 1, 'device_name': 1, 'device_part': 1, 'version': 1, 'device_class': 1})
        if firmware is not None:
            part = ' -' if 'device_part' not in firmware or firmware['device_part'] == '' else ' - {}'.format(firmware['device_part'])
            return '{} {}{} {} ({})'.format(firmware['vendor'], firmware['device_name'], part, firmware['version'], firmware['device_class'])
        return None

    def _get_hid_fo(self, uid, root_uid):
        file_object = self.file_objects.find_one({'_id': uid}, {'virtual_file_path': 1})
        if file_object is not None:
            return self._get_one_virtual_path_of_fo(file_object, root_uid)
        return None

    def all_uids_found_in_database(self, uid_list):
        if not uid_list:
            return True
        query = self._build_search_query_for_uid_list(uid_list)
        number_of_results = self.get_firmware_number(query) + self.get_file_object_number(query)
        return len(uid_list) == number_of_results

    def generic_search(self, search_dict, skip=0, limit=0, only_fo_parent_firmware=False):
        try:
            if isinstance(search_dict, str):
                search_dict = json.loads(search_dict)

            query = self.firmwares.find(search_dict, {'_id': 1}, skip=skip, limit=limit, sort=[('vendor', 1)])
            result = [match['_id'] for match in query]

            if len(result) < limit or limit == 0:
                max_firmware_results = self.get_firmware_number(query=search_dict)
                skip_fo = skip - max_firmware_results if skip > max_firmware_results else 0
                limit_fo = limit - len(result) if limit > 0 else 0
                if not only_fo_parent_firmware:
                    query = self.file_objects.find(search_dict, {'_id': 1}, skip=skip_fo, limit=limit_fo, sort=[('file_name', 1)])
                    result.extend([match['_id'] for match in query])
                else:  # only searching for parents of matching file objects
                    query = self.file_objects.find(search_dict, {'virtual_file_path': 1})
                    parent_uids = {uid for match in query for uid in match['virtual_file_path'].keys()}
                    query_filter = {'$nor': [{'_id': {'$nin': list(parent_uids)}}, search_dict]}
                    query = self.firmwares.find(query_filter, {'_id': 1}, skip=skip_fo, limit=limit_fo, sort=[('file_name', 1)])
                    parents = [match['_id'] for match in query]
                    result = remove_duplicates_from_list(result + parents)

        except Exception as exception:
            error_message = 'could not process search request: {} {}'.format(sys.exc_info()[0].__name__, exception)
            logging.warning(error_message)
            return error_message
        return result

    def get_other_versions_of_firmware(self, firmware_object):
        if not isinstance(firmware_object, Firmware):
            return []
        query = {'vendor': firmware_object.vendor, 'device_name': firmware_object.device_name, 'device_part': firmware_object.part}
        results = self.firmwares.find(query, {'_id': 1, 'version': 1})
        return [r for r in results if r['_id'] != firmware_object.get_uid()]

    def get_specific_fields_for_multiple_entries(self, uid_list, field_dict):
        query = self._build_search_query_for_uid_list(uid_list)
        file_object_iterator = self.file_objects.find(query, field_dict)
        firmware_iterator = self.firmwares.find(query, field_dict)
        return merge_generators(firmware_iterator, file_object_iterator)

    # --- statistics

    def get_last_added_firmwares(self, limit_x=10):
        latest_firmwares = self.firmwares.find(
            {'submission_date': {'$gt': 1}}, limit=limit_x, sort=[('submission_date', -1)]
        )
        return self.get_meta_list(latest_firmwares)

    def get_latest_comments(self, limit=10):
        comments = []
        for collection in [self.firmwares, self.file_objects]:
            db_entries = collection.aggregate([
                {'$match': {'comments': {'$not': {'$size': 0}}}},
                {'$project': {'_id': 1, 'comments': 1}},
                {'$unwind': {'path': '$comments'}},
                {'$sort': {'comments.time': -1}},
                {'$limit': limit}
            ])
            comments.extend([
                {**entry['comments'], 'uid': entry['_id']}  # caution: >=python3.5 exclusive syntax
                for entry in db_entries if entry['comments']
            ])
        comments.sort(key=lambda x: x['time'], reverse=True)
        return comments

    # --- file tree

    def _create_node_from_virtual_path(self, uid, root_uid, current_virtual_path, fo_data, whitelist=None):
        if len(current_virtual_path) > 1:  # in the middle of a virtual file path
            node = FileTreeNode(uid=None, root_uid=root_uid, virtual=True, name=current_virtual_path.pop(0))
            for child_node in self.generate_file_tree_node(uid, root_uid, current_virtual_path=current_virtual_path, fo_data=fo_data, whitelist=whitelist):
                node.add_child_node(child_node)
        else:  # at the end of a virtual path aka a 'real' file
            if whitelist:
                has_children = any(f in fo_data['files_included'] for f in whitelist)
            else:
                has_children = fo_data['files_included'] != []
            mime_type = fo_data['processed_analysis']['file_type']['mime'] if 'file_type' in fo_data['processed_analysis'] else 'file-type-plugin/not-run-yet'
            node = FileTreeNode(uid, root_uid=root_uid, virtual=False, name=fo_data['file_name'], size=fo_data['size'], mime_type=mime_type, has_children=has_children)
        return node

    def generate_file_tree_node(self, uid, root_uid, current_virtual_path=None, fo_data=None, whitelist=None):
        required_fields = {'virtual_file_path': 1, 'files_included': 1, 'file_name': 1, 'size': 1, 'processed_analysis.file_type.mime': 1, '_id': 1}
        if fo_data is None:
            fo_data = self.get_specific_fields_of_db_entry({'_id': uid}, required_fields)
        try:
            if root_uid not in fo_data['virtual_file_path']:  # file tree for a file object (instead of a firmware)
                fo_data['virtual_file_path'] = get_partial_virtual_path(fo_data['virtual_file_path'], root_uid)
            if current_virtual_path is None:
                for entry in fo_data['virtual_file_path'][root_uid]:  # the same file may occur several times with different virtual paths
                    current_virtual_path = entry.split('/')[1:]
                    yield self._create_node_from_virtual_path(uid, root_uid, current_virtual_path, fo_data, whitelist)
            else:
                yield self._create_node_from_virtual_path(uid, root_uid, current_virtual_path, fo_data, whitelist)
        except Exception:  # the requested data is not present in the DB aka the file has not been analyzed yet
            yield FileTreeNode(uid=uid, root_uid=root_uid, not_analyzed=True, name='{} (not analyzed yet)'.format(uid))

    def get_number_of_total_matches(self, query, only_parent_firmwares):
        if not only_parent_firmwares:
            return self.get_firmware_number(query=query) + self.get_file_object_number(query=query)
        if isinstance(query, str):
            query = json.loads(query)
        fw_matches = {match['_id'] for match in self.firmwares.find(query)}
        fo_matches = {parent for match in self.file_objects.find(query)
                      for parent in match['virtual_file_path'].keys()} if query != {} else set()
        return len(fw_matches.union(fo_matches))

    def create_analysis_structure(self):
        if self.client.varietyResults.file_objectsKeys.count_documents({}) == 0:
            return 'Database statistics do not seem to be created yet.'

        file_object_keys = self.client.varietyResults.file_objectsKeys.find()
        all_field_strings = list(
            key_item['_id']['key'] for key_item in file_object_keys
            if key_item['_id']['key'].startswith('processed_analysis')
            and key_item['percentContaining'] >= float(self.config['data_storage']['structural_threshold'])
        )
        stripped_field_strings = list(field[len('processed_analysis.'):] for field in all_field_strings if field != 'processed_analysis')

        return visualize_complete_tree(stripped_field_strings)

    def rest_get_firmware_uids(self, offset, limit, query=None, recursive=False):
        if recursive:
            return self.generic_search(search_dict=query, skip=offset, limit=limit, only_fo_parent_firmware=True)
        return self.rest_get_object_uids(self.firmwares, offset, limit, query if query else dict())

    def rest_get_file_object_uids(self, offset, limit, query=None):
        return self.rest_get_object_uids(self.file_objects, offset, limit, query if query else dict())

    @staticmethod
    def rest_get_object_uids(database, offset, limit, query):
        uid_cursor = database.find(query, {'_id': 1}).skip(offset).limit(limit)
        return [result['_id'] for result in uid_cursor]
