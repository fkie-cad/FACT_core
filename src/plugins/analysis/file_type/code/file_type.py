from fact_helper_file import get_file_type_from_path

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    """
    This Plugin detects the mime type of the file
    """

    NAME = 'file_type'
    DESCRIPTION = 'identify the file type'
    VERSION = '1.0'
    FILE = __file__

    def process_object(self, file_object):
        """
        This function must be implemented by the plugin.
        Analysis result must be a list stored in file_object.processed_analysis[self.NAME]
        """
        file_type = get_file_type_from_path(file_object.file_path)
        file_object.processed_analysis[self.NAME] = file_type
        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(
            file_object.processed_analysis[self.NAME]
        )
        return file_object

    @staticmethod
    def _get_summary(results):
        return [results['mime']]
