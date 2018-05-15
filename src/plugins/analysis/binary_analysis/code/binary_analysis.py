from analysis.RemotePluginBase import RemoteBasePlugin


class AnalysisPlugin(RemoteBasePlugin):
    NAME = 'binary_analysis'
    DESCRIPTION = 'this is a remote analysis test plugin'
    VERSION = '0.3'
    FILE = __file__

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=None):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=plugin_path)
