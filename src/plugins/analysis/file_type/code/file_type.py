from analysis.PluginBase import BasePlugin
from helperFunctions.fileSystem import get_file_type_from_path


class AnalysisPlugin(BasePlugin):
    '''
    This Plugin detects the mime type of the file
    '''
    NAME = "file_type"
    DESCRIPTION = "identify the file type"
    VERSION = "0.1.1"

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        propagate flag: If True add analysis result of child to parent object
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config

        # additional init stuff can go here

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        '''
        This function must be implemented by the plugin.
        Analysis result must be a list stored in file_object.processed_analysis[self.NAME]
        '''
        file_type = get_file_type_from_path(file_object.file_path)
        file_object.processed_analysis[self.NAME] = file_type
        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(file_object.processed_analysis[self.NAME])
        return file_object

    @staticmethod
    def _get_summary(results):
        summary = [results['mime']]
        return summary
