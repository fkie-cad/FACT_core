from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This is a mock for testing
    '''
    NAME = "dummy_plugin_for_testing_only"
    DEPENDENCIES = []
    VERSION = "0.0"
    DESCRIPTION = "this is a dummy plugin"

    def __init__(self, config=None):
        super().__init__(config=config)

    def process_object(self, file_object):
        file_object.processed_analysis[self.NAME] = {'1': "first result", '2': "second result"}
        file_object.processed_analysis[self.NAME]['summary'] = ['first result', 'second result']
        return file_object
