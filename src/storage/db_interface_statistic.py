import logging
from typing import List

from pymongo.errors import PyMongoError

from storage.mongo_interface import MongoInterface


class StatisticDb(MongoInterface):
    '''
    Statistic Module Database Binding
    '''

    def __init__(self, config=None):
        super().__init__(config=config)

    def _setup_database_mapping(self):
        self.main_collection = self.client[self.config['data_storage']['main_database']]
        self.firmwares = self.main_collection.firmwares
        self.file_objects = self.main_collection.file_objects
        self.statistic_collection = self.client[self.config['data_storage']['statistic_database']]
        self.statistic = self.statistic_collection.statistic


class StatisticDbUpdater(StatisticDb):
    '''
    Statistic module backend interface
    '''

    READ_ONLY = False

    def update_statistic(self, identifier, content_dict):
        logging.debug("update {} statistic".format(identifier))
        try:
            self.statistic.delete_many({'_id': identifier})
            content_dict['_id'] = identifier
            self.statistic.insert_one(content_dict)
        except PyMongoError as err:
            logging.error(f"Could not store statistic {identifier} ({err})", exc_info=True)


class StatisticDbViewer(StatisticDb):
    '''
    Statistic module frontend interface
    '''

    READ_ONLY = True

    def get_statistic(self, identifier):
        return self.statistic.find_one({'_id': identifier})

    def get_stats_list(self, *identifiers: str) -> List[dict]:
        return list(self.statistic.find({'_id': {'$in': identifiers}}))
