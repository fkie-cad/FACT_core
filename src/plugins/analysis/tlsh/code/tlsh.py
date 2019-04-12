from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.hash import get_tlsh_compairson
from storage.db_interface_common import MongoInterfaceCommon
from helperFunctions.web_interface import ConnectTo


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    TLSH Plug-in
    '''
    NAME = 'tlsh'
    DESCRIPTION = 'find files with similar tlsh and calculate similarity value'
    DEPENDENCIES = ['binwalk', 'base64_decoder', 'file_system_metadata', 'file_hashes']
    VERSION = '0.1'

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        '''
        self.config = config

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):

        comparisons_dict = {}
        tlsh = {}

        if 'tlsh' in file_object.processed_analysis['file_hashes'].keys():

            comparisons_dict = {}

            with ConnectTo(TLSHInterface, self.config) as interface:

                for files in interface.tlsh_query(file_object):
                    try:
                        value = get_tlsh_compairson(file_object.processed_analysis['file_hashes']['tlsh'],
                                                    files['processed_analysis']['file_hashes']['tlsh'])
                        if value < 1000:
                            comparisons_dict[files['_id']] = value

                    except:
                        print("TLSH comparison not possible.")

                    pass

        tlsh['tlsh'] = comparisons_dict
        file_object.processed_analysis[self.NAME] = tlsh

        return file_object


class TLSHInterface(MongoInterfaceCommon):
    READ_ONLY = True

    def tlsh_query(self, file_object):
        return self.file_objects.find({"processed_analysis.file_hashes.tlsh": {"$exists": True}})
