import sys
from pathlib import Path

from analysis.PluginBase import AnalysisBasePlugin

try:
    from ..internal.string_eval import eval_strings
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from string_eval import eval_strings


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Sort strings by relevance

    Credits:
    Original version by Paul Schiffer created during Firmware Bootcamp WT16/17 at University of Bonn
    Refactored and improved by Fraunhofer FKIE
    '''
    NAME = 'string_evaluator'
    DEPENDENCIES = ['printable_strings']
    MIME_BLACKLIST = ['application/gzip', 'application/gzip', 'application/x-7z-compressed', 'application/x-tar', 'application/x-xz', 'application/zip']
    DESCRIPTION = 'Tries to sort strings based on usefulness'
    VERSION = '0.2.1'

    def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
        super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

    def process_object(self, file_object):
        list_of_printable_strings = file_object.processed_analysis['printable_strings']['strings']
        file_object.processed_analysis[self.NAME] = dict(string_eval=eval_strings(list_of_printable_strings))
        return file_object
