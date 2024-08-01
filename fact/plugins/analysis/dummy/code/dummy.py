from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    """
    This is a mock for testing
    """

    NAME = 'dummy_plugin_for_testing_only'
    DEPENDENCIES = []  # noqa: RUF012
    VERSION = '0.0'
    DESCRIPTION = 'this is a dummy plugin'
    FILE = __file__

    def process_object(self, file_object):
        """
        This function must be implemented by the plugin.
        Analysis result must be a list stored in file_object.processed_analysis[self.NAME]
        """
        file_object.processed_analysis[self.NAME] = {'1': 'first result', '2': 'second result'}
        file_object.processed_analysis[self.NAME]['summary'] = ['first result', 'second result']
        return file_object
