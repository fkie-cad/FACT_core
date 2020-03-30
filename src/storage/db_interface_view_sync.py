import logging

import gridfs
from common_helper_mongo.gridfs import overwrite_file

from storage.mongo_interface import MongoInterface


class ViewSyncDb(MongoInterface):
    '''
    View Syncing
    '''
    def __init__(self, config=None):
        super().__init__(config=config)
        self.view_collection = self.client[self.config['data_storage']['view_storage']]
        self.view_storage = gridfs.GridFS(self.view_collection)


class ViewUpdater(ViewSyncDb):

    READ_ONLY = False

    def update_view(self, file_name, content):
        overwrite_file(self.view_storage, file_name, content)
        logging.debug('view updated: {}'.format(file_name))


class ViewReader(ViewSyncDb):

    READ_ONLY = True

    def get_view(self, plugin_name):
        view = self.view_storage.find_one({'filename': '{}'.format(plugin_name)})
        if view:
            return view.read()
        return None
