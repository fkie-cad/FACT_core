from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.strings import find_all_strings


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Extracts all printable Strings
    '''
    NAME = 'printable_strings'
    DEPENDENCIES = []
    DESCRIPTION = 'extracts strings and their offsets from the files consisting of printable characters'
    VERSION = '0.3'

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=__file__):
        '''
        recursive flag: If True recursively analyze included files
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=plugin_path)

    def process_object(self, file_object):
        strings, offsets = self._get_strings_and_offsets(file_object.binary)
        file_object.processed_analysis[self.NAME] = {
            'strings': strings,
            'offsets': offsets
        }
        return file_object

    def _get_strings_and_offsets(self, binary):
        min_length = self.config[self.NAME]['min_length']
        strings = find_all_strings(binary, min_length=min_length)
        offsets = self._find_offsets(strings, binary)
        return strings, offsets

    @staticmethod
    def _find_offsets(string_list, binary):
        result = []
        for string in string_list:
            offset = -1
            while True:
                offset = binary.find(string.encode(), offset + 1)
                if offset == -1:
                    break
                result.append((offset, string))
        return result

    @staticmethod
    def _get_summary(match_dict):
        return list(match_dict.keys())
