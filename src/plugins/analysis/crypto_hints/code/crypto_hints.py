from analysis.YaraPluginBase import YaraBasePlugin


class AnalysisPlugin(YaraBasePlugin):

    NAME = 'crypto_hints'
    DESCRIPTION = 'find indicators of specific crypto algorithms'
    DEPENDENCIES = []
    VERSION = '0.1.1'
    FILE = __file__
