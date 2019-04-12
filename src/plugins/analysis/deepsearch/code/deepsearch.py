from analysis.PluginBase import AnalysisBasePlugin

from helperFunctions.web_interface import ConnectTo

from storage.db_interface_common import MongoInterfaceCommon

import time


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

        #result_object = file_object
        #result_strings = file_object.processed_analysis['printable_strings']
        #result_file_type = file_object.processed_analysis['file_type']

        #gives runtime error
        #file_object.processed_analysis[self.NAME] = dict()

        #file_object.processed_analysis[self.NAME]['object'] = str(result_object)
        #file_object.processed_analysis[self.NAME]['file_type'] = str(result_file_type)
        #file_object.processed_analysis[self.NAME]['strings'] = str(result_strings)

        # result_a = 'hello world'
        # result_b = "new value"
        #file_object.processed_analysis[self.NAME]['analysis_result_a'] = result_a
        #file_object.processed_analysis[self.NAME]['analysis_result_b'] = result_b
        #file_object.processed_analysis[self.NAME]['summary'] = ['{} - {}'.format(result_a, result_b)]

        '''
       for ele in collection.find():

           if firmware_id in ele["parent_firmware_uids"]:
               tmp = dict()
               path = ele["virtual_file_path"]
               path_str = list(path.values())[0]
               path_str = path_str[0]
               path_str = path_str[path_str.index("/"):]
               #print(path_str)

               tmp["path"] = path_str
               tmp["name"] = ele["file_name"]

               executables.append(tmp)

           else:
               continue
        '''

        analysisdictionary = {}

        fileid = file_object.uid
        firmware_id = ""

        #time.sleep(5)

        with ConnectTo(BinaryInterface, self.config) as interface:
            for element in interface.firmwareIDofFileID(fileid):
                firmware_id = element['parent_firmware_uids'][0]

            analysisdictionary['contained_binaries'] = list()

            for printstring in file_object.processed_analysis['printable_strings']['strings']:
                for executablefile in interface.executableFiles(firmware_id):
                    if executablefile['parent_firmware_uids'] == firmware_id:
                        if executablefile['file_name'] in printstring:
                            #file_object.processed_analysis[self.NAME]['contained_binaries'].append(executablefile)
                            analysisdictionary['contained_binaries'].append(executablefile)

                    pass

            file_object.processed_analysis[self.NAME] = analysisdictionary




        return file_object


class BinaryInterface(MongoInterfaceCommon):

    READ_ONLY = True

    def firmwareIDofFileID(self, file_id):
        return self.file_objects.find({"processed_analysis._uid": file_id})

    def executableFiles(self, firmware_id):
        #return self.file_objects.find({"processed_analysis.file_type.mime": {"$regex": "executable"}, "parent_firmware_uids": firmware_id})
        return self.file_objects.find(
            {"$or": [{"processed_analysis.file_type.mime": {"$regex": "executable"}, "parent_firmware_uids": firmware_id},
                     {"processed_analysis.file_type.mime": {"$regex": "application"}, "parent_firmware_uids": firmware_id}]})