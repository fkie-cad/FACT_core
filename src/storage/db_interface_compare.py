import logging
from time import time
from typing import Optional

from helperFunctions.dataConversion import (
    convert_compare_id_to_list, convert_uid_list_to_compare_id,
    normalize_compare_id
)
from storage.db_interface_common import MongoInterfaceCommon


class FactCompareException(Exception):
    def get_message(self):
        if self.args:
            return self.args[0]
        return ''


class CompareDbInterface(MongoInterfaceCommon):

    def _setup_database_mapping(self):
        super()._setup_database_mapping()
        self.compare_results = self.main.compare_results

    def add_compare_result(self, compare_result):
        compare_result['_id'] = self._calculate_compare_result_id(compare_result)
        compare_result['submission_date'] = time()
        try:
            self.compare_results.delete_one({'_id': compare_result['_id']})
        except Exception:
            pass
        self.compare_results.insert_one(compare_result)
        logging.info('compare result added to db: {}'.format(compare_result['_id']))

    def get_compare_result(self, compare_id: str) -> Optional[dict]:
        compare_id = normalize_compare_id(compare_id)
        self.check_objects_exist(compare_id)
        compare_result = self.compare_results.find_one(compare_id)
        if compare_result:
            logging.debug('got compare result from db: {}'.format(compare_id))
            return compare_result
        logging.debug('compare result not found in db: {}'.format(compare_id))
        return None

    def check_objects_exist(self, compare_id):
        uids = convert_compare_id_to_list(compare_id)
        for uid in uids:
            if not self.existence_quick_check(uid):
                raise FactCompareException('{} not found in database'.format(uid))

    def compare_result_is_in_db(self, compare_id):
        compare_result = self.compare_results.find_one(normalize_compare_id(compare_id))
        return True if compare_result else False

    def delete_old_compare_result(self, compare_id):
        try:
            self.compare_results.remove({'_id': normalize_compare_id(compare_id)})
            logging.debug('old compare result deleted: {}'.format(compare_id))
        except Exception as exception:
            logging.warning('Could not delete old compare result: {} {}'.format(type(exception).__name__, exception))

    @staticmethod
    def _calculate_compare_result_id(compare_result):
        general_dict = compare_result['general']
        uid_set = set()
        for key in general_dict:
            uid_set.update(list(general_dict[key].keys()))
        comp_id = convert_uid_list_to_compare_id(list(uid_set))
        return comp_id

    def page_compare_results(self, skip=0, limit=0):
        db_entries = self.compare_results.find({'submission_date': {'$gt': 1}}, {'general.hid': 1, 'submission_date': 1}, skip=skip, limit=limit, sort=[('submission_date', -1)])
        all_previous_results = [(item['_id'], item['general']['hid'], item['submission_date']) for item in db_entries]
        return [
            compare
            for compare in all_previous_results
            if self._all_objects_are_in_db(compare[0])
        ]

    def _all_objects_are_in_db(self, compare_id):
        try:
            self.check_objects_exist(compare_id)
            return True
        except FactCompareException:
            return False

    def get_total_number_of_results(self):
        db_entries = self.compare_results.find({'submission_date': {'$gt': 1}}, {'_id': 1})
        return sum(1 for entry in db_entries if not self.check_objects_exist(entry['_id']))  # sum(1 for... calculates length of generator

    def get_ssdeep_hash(self, uid):
        file_object_entry = self.file_objects.find_one({'_id': uid}, {'processed_analysis.file_hashes.ssdeep': 1})
        return file_object_entry['processed_analysis']['file_hashes']['ssdeep'] if 'file_hashes' in file_object_entry['processed_analysis'] else None

    def get_entropy(self, uid):
        file_object_entry = self.file_objects.find_one({'_id': uid}, {'processed_analysis.unpacker.entropy': 1})
        return file_object_entry['processed_analysis']['unpacker']['entropy'] if 'unpacker' in file_object_entry['processed_analysis'] else 0.0
