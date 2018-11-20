import lief
import json
from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'elf_analysis'
    DESCRIPTION = 'Elf Analysis Plug-in'
    DEPENDENCIES = ['file_type']
    VERSION = '0.1'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']

    def __init__(self, plugin_adminstrator, config=None, recursive=True):

        '''
        recursive flag: If True recursively analyze included files
        '''

        self.config = config

        # additional init stuff can go here

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):

        '''
        This function must be implemented by the plug-in.
        Analysis result must be a dict stored in "file_object.processed_analysis[self.NAME]"
        CAUTION: Dict keys must be strings!
        If you want to propagate results to parent objects store a list of strings in
        "file_object.processed_analysis[self.NAME]['summary']".

        File's binary is available via "file_object.binary".
        File's local storage path is available via "file_object.file_path".
        Results of other plug-ins can be accesd via "file_object.processed_analysis['PLUGIN_NAME']".
        Do not forget to add these plug-ins to "DEPENDENCIES".
        '''

        # do some fancy stuff

        result = {}
        elf_dict = self._analyze_elf(file_object)

        result['Output'] = elf_dict

        file_object.processed_analysis[self.NAME] = result
        file_object.processed_analysis[self.NAME]['summary'] = list(elf_dict.keys())
        return file_object

    def _analyze_elf(self, file_object: FileObject):

        elf_dict = {}

        try:
            parsed_binary = lief.parse(raw=file_object.binary)
            binary_json_dict = json.loads(lief.to_json_from_abstract(parsed_binary))
            if parsed_binary.exported_functions:
                binary_json_dict['exported_functions'] = parsed_binary.exported_functions
            if parsed_binary.imported_functions:
                binary_json_dict['imported_functions'] = parsed_binary.imported_functions
        except TypeError:
            print('Type Error')
            return elf_dict
        except lief.bad_file:
            print('Bad File, UID: ', file_object.get_uid())
            return elf_dict

        # TODO make this an extra function
        for key in binary_json_dict:
            if key in ('header', 'segments', 'sections', 'dynamic_entries', 'exported_functions', 'imported_functions'):
                elf_dict[key] = binary_json_dict[key]

        return elf_dict
