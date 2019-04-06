from analysis.PluginBase import AnalysisBasePlugin

import pymongo

class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Deep Search Plug-in
    '''
    NAME = 'deepsearch'
    DESCRIPTION = 'DeepSearch Plug-in'
    DEPENDENCIES = ["elf_analysis", "printable_strings", "file_type"]
    VERSION = '0.1'

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        '''
        self.config = config

        # additional init stuff can go here

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)
    

    def process_object(self, file_object):


        #db.getCollection('file_objects').find({ "processed_analysis.file_type.mime": "application/x-executable"  })

        # do some fancy stuff
        result_a = 'hello world'
        result_b = "new value"
        result_object = file_object
        result_strings = file_object.processed_analysis['printable_strings']
        result_file_type = file_object.processed_analysis['file_type']

        file_object.processed_analysis[self.NAME] = dict()
        file_object.processed_analysis[self.NAME]['analysis_result_a'] = result_a
        file_object.processed_analysis[self.NAME]['analysis_result_b'] = result_b
        file_object.processed_analysis[self.NAME]['object'] = str(result_object)
        file_object.processed_analysis[self.NAME]['file_type'] = str(result_file_type)
        file_object.processed_analysis[self.NAME]['strings'] = str(result_strings)



        file_object.processed_analysis[self.NAME]['summary'] = ['{} - {}'.format(result_a, result_b)]

        user_ro = "fact_readonly"
        password_ro = "RFaoFSr8b6BMSbzt"
        user_write = 'fact_admin'
        password_write = '6fJEb5LkV2hRtWq0'
        url = "localhost"
        port = "27018"

        connection = pymongo.MongoClient(
            "mongodb://" + user_write + ":" + password_write
            + "@" + url + ":" + port + "/?authSource=admin&authMechanism=SCRAM-SHA-1")

        admin_db = connection["fact_main"]

        collection = admin_db["file_objects"]
        fileid = file_object.uid

        firmware_id = ""
        for element in collection.find({"_id": fileid}):
            firmware_id = element["parent_firmware_uids"][0]



        return file_object
