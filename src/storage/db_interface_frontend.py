import json
import logging
import sys
from copy import deepcopy

from helperFunctions.compare_sets import remove_duplicates_from_list
from helperFunctions.database_structure import visualize_complete_tree
from helperFunctions.dataConversion import get_value_of_first_key
from helperFunctions.file_tree import FileTreeNode, VirtualPathFileTree
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

    def get_query_from_cache(self, query):
        return self.search_query_cache.find_one({'_id': query})

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
                    'current_virtual_path': virtual_file_path[root_uid] if root_uid in virtual_file_path else get_value_of_first_key(virtual_file_path)
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
        return number_of_results >= len(uid_list)

    def generic_search(self, search_dict, skip=0, limit=0, only_fo_parent_firmware=False, inverted=False):
        try:
            if isinstance(search_dict, str):
                search_dict = json.loads(search_dict)

            if not (inverted and only_fo_parent_firmware):
                query = self.firmwares.find(search_dict, {'_id': 1}, skip=skip, limit=limit, sort=[('vendor', 1)])
                result = [match['_id'] for match in query]
            else:
                result = []

            if len(result) < limit or limit == 0:
                max_firmware_results = self.get_firmware_number(query=search_dict)
                skip = skip - max_firmware_results if skip > max_firmware_results else 0
                limit = limit - len(result) if limit > 0 else 0
                if not only_fo_parent_firmware:
                    query = self.file_objects.find(search_dict, {'_id': 1}, skip=skip, limit=limit, sort=[('file_name', 1)])
                    result.extend([match['_id'] for match in query])
                else:  # only searching for parents of matching file objects
                    parent_uids = self.file_objects.distinct('parent_firmware_uids', search_dict)
                    query_filter = {'$nor': [{'_id': {('$in' if inverted else '$nin'): parent_uids}}, search_dict]}
                    query = self.firmwares.find(query_filter, {'_id': 1}, skip=skip, limit=limit, sort=[('file_name', 1)])
                    parents = [match['_id'] for match in query]
                    result = remove_duplicates_from_list(result + parents)

        except Exception as exception:
            error_message = 'could not process search request: {} {}'.format(sys.exc_info()[0].__name__, exception)
            logging.warning(error_message)
            return error_message
        return result

    def get_other_versions_of_firmware(self, firmware_object: Firmware):
        if not isinstance(firmware_object, Firmware):
            return []
        query = {'vendor': firmware_object.vendor, 'device_name': firmware_object.device_name, 'device_part': firmware_object.part}
        results = self.firmwares.find(query, {'_id': 1, 'version': 1})
        return [r for r in results if r['_id'] != firmware_object.uid]

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
            ], allowDiskUse=True)
            comments.extend([
                {**entry['comments'], 'uid': entry['_id']}  # caution: >=python3.5 exclusive syntax
                for entry in db_entries if entry['comments']
            ])
        comments.sort(key=lambda x: x['time'], reverse=True)
        return comments

    # --- file tree

    def generate_file_tree_nodes_for_uid_list(self, uid_list, root_uid, whitelist=None):
        query = self._build_search_query_for_uid_list(uid_list)
        fo_data = self.file_objects.find(query, VirtualPathFileTree.FO_DATA_FIELDS)
        fo_data_dict = {entry['_id']: entry for entry in fo_data}
        for uid in uid_list:
            fo_data_entry = fo_data_dict[uid] if uid in fo_data_dict else {}
            for node in self.generate_file_tree_level(uid, root_uid, whitelist, fo_data_entry):
                yield node

    def generate_file_tree_level(self, uid, root_uid, whitelist=None, fo_data=None):
        if fo_data is None:
            fo_data = self.get_specific_fields_of_db_entry({'_id': uid}, VirtualPathFileTree.FO_DATA_FIELDS)
        try:
            for node in VirtualPathFileTree(root_uid, fo_data, whitelist).get_file_tree_nodes():
                yield node
        except (KeyError, TypeError):  # the requested data is not in the DB aka the file has not been analyzed yet
            yield FileTreeNode(uid, root_uid, not_analyzed=True, name='{uid} (not analyzed yet)'.format(uid=uid))

    def get_number_of_total_matches(self, query, only_parent_firmwares, inverted):
        if not only_parent_firmwares:
            return self.get_firmware_number(query=query) + self.get_file_object_number(query=query)
        if isinstance(query, str):
            query = json.loads(query)
        direct_matches = {match['_id'] for match in self.firmwares.find(query, {'_id': 1})} if not inverted else set()
        if query == {}:
            return len(direct_matches)
        parent_matches = {
            parent for match in self.file_objects.find(query, {'parent_firmware_uids': 1})
            for parent in match['parent_firmware_uids']
        }
        if inverted:
            parent_matches = {match['_id'] for match in self.firmwares.find({'_id': {'$nin': list(parent_matches)}}, {'_id': 1})}
        return len(direct_matches.union(parent_matches))

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

    def rest_get_firmware_uids(self, offset, limit, query=None, recursive=False, inverted=False):
        if recursive:
            return self.generic_search(search_dict=query, skip=offset, limit=limit, only_fo_parent_firmware=True, inverted=inverted)
        return self.rest_get_object_uids(self.firmwares, offset, limit, query if query else dict())

    def rest_get_file_object_uids(self, offset, limit, query=None):
        return self.rest_get_object_uids(self.file_objects, offset, limit, query if query else dict())

    @staticmethod
    def rest_get_object_uids(database, offset, limit, query):
        uid_cursor = database.find(query, {'_id': 1}).skip(offset).limit(limit)
        return [result['_id'] for result in uid_cursor]

    def find_missing_files(self):
        uids_in_db = set()
        parent_to_included = {}
        for collection in [self.file_objects, self.firmwares]:
            for result in collection.find({}, {'_id': 1, 'files_included': 1}):
                uids_in_db.add(result['_id'])
                parent_to_included[result['_id']] = set(result['files_included'])
        for parent_uid, included_files in list(parent_to_included.items()):
            included_files.difference_update(uids_in_db)
            if not included_files:
                parent_to_included.pop(parent_uid)
        return parent_to_included

    def find_missing_analyses(self):
        missing_analyses = {}
        query_result = self.firmwares.aggregate([
            {'$project': {'temp': {'$objectToArray': '$processed_analysis'}}},
            {'$unwind': '$temp'},
            {'$group': {'_id': '$_id', 'analyses': {'$addToSet': '$temp.k'}}},
        ], allowDiskUse=True)
        for result in query_result:
            firmware_uid, analysis_list = result['_id'], result['analyses']
            query = {"$and": [
                {"virtual_file_path.{}".format(firmware_uid): {"$exists": True}},
                {"$or": [{"processed_analysis.{}".format(plugin): {"$exists": False}} for plugin in analysis_list]}
            ]}
            for entry in self.file_objects.find(query, {'_id': 1}):
                missing_analyses.setdefault(firmware_uid, set()).add(entry['_id'])
        return missing_analyses
