import logging
import sys

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
        except Exception as e:
            logging.error("Could not store statistic {}: {} - {}".format(identifier, sys.exc_info()[0].__name__, e))


class StatisticDbViewer(StatisticDb):
    '''
    Statistic module frontend interface
    '''

    READ_ONLY = True

    def get_statistic(self, identifier):
        return self.statistic.find_one({'_id': identifier})
