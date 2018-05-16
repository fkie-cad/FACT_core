from typing import List, Tuple

from analysis.YaraPluginBase import YaraBasePlugin


class AnalysisPlugin(YaraBasePlugin):
    '''
    Extracts all printable Strings
    '''
    NAME = 'printable_strings'
    DEPENDENCIES = []
    DESCRIPTION = 'extracts strings and their offsets from the files consisting of printable characters'
    VERSION = '0.3'

    RULE_NAME = 'PrintableString'

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=__file__):
        '''
        recursive flag: If True recursively analyze included files
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=plugin_path)

    def process_object(self, file_object):
        super().process_object(file_object)
        strings, offsets = self._extract_strings_and_offsets_from_yara_results(file_object.processed_analysis[self.NAME])
        file_object.processed_analysis[self.NAME] = {
            'strings': strings,
            'offsets': offsets
        }
        return file_object

    def _extract_strings_and_offsets_from_yara_results(self, yara_results: dict) -> Tuple[List[str], List[Tuple[int, str]]]:
        strings, offsets = set(), []
        last_offset = 0
        if self.RULE_NAME in yara_results:
            for offset, _, string in yara_results[self.RULE_NAME]['strings']:
                if last_offset == 0 or self._is_overlap(offset, last_offset, len(string)):
                    string = string.decode()
                    offsets.append((offset, string))
                    strings.add(string)
                    last_offset = offset
        return list(strings), offsets

    @staticmethod
    def _is_overlap(current_offset: int, last_offset: int, match_length: int) -> bool:
        return current_offset - last_offset > match_length

    def _get_summary(self, match_dict):
        return list(match_dict.keys())
