from analysis.PluginBase import AnalysisBasePlugin
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED

from ..internal.string_eval import eval_strings


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Sort strings by relevance

    Credits:
    Original version by Paul Schiffer created during Firmware Bootcamp WT16/17 at University of Bonn
    Refactored and improved by Fraunhofer FKIE
    '''

    NAME = 'string_evaluator'
    DEPENDENCIES = ['printable_strings']
    MIME_BLACKLIST = MIME_BLACKLIST_COMPRESSED
    DESCRIPTION = 'Tries to sort strings based on usefulness'
    VERSION = '0.2.1'
    FILE = __file__

    def process_object(self, file_object):
        list_of_printable_strings = file_object.processed_analysis['printable_strings']['result']['strings']
        file_object.processed_analysis[self.NAME] = dict(string_eval=eval_strings(list_of_printable_strings))
        return file_object
