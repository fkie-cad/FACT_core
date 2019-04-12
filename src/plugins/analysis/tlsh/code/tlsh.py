from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.hash import get_tlsh, get_tlsh_compairson
import time
import pymongo

from storage.db_interface_common import MongoInterfaceCommon


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    TLSH Plug-in
    '''
    NAME = 'tlsh'
    DESCRIPTION = 'Calculate TLSH similarity'
    DEPENDENCIES = ['binwalk', 'base64_decoder', 'file_system_metadata', 'file_hashes']
    VERSION = '0.1'

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        '''
        self.config = config

        # additional init stuff can go here

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):

        # file_object.processed_analysis[self.NAME] = dict()
        # file_object.processed_analysis[self.NAME]['summary'] = ['{} - {}'.format(result_a, result_b)]

        dictcomp = {}

        if 'tlsh' in file_object.processed_analysis['file_hashes'].keys():

            time.sleep(1)

            user_write = 'fact_admin'
            password_write = '6fJEb5LkV2hRtWq0'
            url = "localhost"
            port = "27018"

            connection = pymongo.MongoClient(
                "mongodb://" + user_write + ":" + password_write
                + "@" + url + ":" + port + "/?authSource=admin&authMechanism=SCRAM-SHA-1")

            admin_db = connection["fact_main"]
            collection = admin_db["file_objects"]

            dictcomp = {}

            with ConnectTo(TLSHInterface, self.config) as interface:

                for files in interface.get_tlsh_objects()():
                    try:

                        dictcomp[files['_id']] = get_tlsh_compairson(file_object.processed_analysis['file_hashes']['tlsh'],
                                                                     files['processed_analysis']['file_hashes']['tlsh'])
                    except:
                        print("TLSH comparison not possible")

                    pass

            connection.close()

        file_object.processed_analysis[self.NAME] = dictcomp

        return file_object


class TLSHInterface(MongoInterfaceCommon):

    READ_ONLY = True

    def parent_fo_has_fs_metadata_analysis_results(self, file_object):
        self.file_objects.find({"processed_analysis.file_hashes.tlsh": {"$exists": True}})
