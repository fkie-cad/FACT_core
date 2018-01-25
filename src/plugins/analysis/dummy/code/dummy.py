from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This is a mock for testing
    '''
    NAME = "dummy_plugin_for_testing_only"
    DEPENDENCIES = []
    VERSION = "0.0"
    DESCRIPTION = "this is a dummy plugin"

    def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
        '''
        recursive flag: If True recursively analyze included files
        propagate flag: If True add analysis result of child to parent object
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout)
        # additional init stuff can go here

    def process_object(self, file_object):
        '''
        This function must be implemented by the plugin.
        Analysis result must be a list stored in file_object.processed_analysis[self.NAME]
        '''
        file_object.processed_analysis[self.NAME] = {'1': "first result", '2': "second result"}
        file_object.processed_analysis[self.NAME]['summary'] = ['first result', 'second result']
        return file_object
