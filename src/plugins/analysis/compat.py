from statistic.analysis_stats import ANALYSIS_STATS_LIMIT


class AnalysisBasePluginAdapterMixin:
    """A mixin that makes PluginV0 ompatible to AnalysisBasePlugin"""

    # pylint: disable=invalid-name

    def start(self):
        # This is a no-op
        pass

    @property
    def FILE(self):
        # What is this even used for?
        raise NotImplementedError

    @property
    def NAME(self):
        return self.metadata.name

    @property
    def DESCRIPTION(self):
        return self.metadata.description

    @property
    def DEPENDENCIES(self):
        return self.metadata.dependencies

    @property
    def VERSION(self):
        return self.metadata.version

    @property
    def RECURSIVE(self):
        return False

    @property
    def TIMEOUT(self):
        return self.metadata.max_duration

    @property
    def SYSTEM_VERSION(self):
        return self.metadata.version

    @property
    def MIME_BLACKLIST(self):
        return self.metadata.mime_blacklist

    @property
    def MIME_WHITELIST(self):
        return self.metadata.mime_whitelist

    @property
    def ANALYSIS_STATS_LIMIT(self):
        # Since no plugin sets this, we just use the default from AnalysisBasePlugin here
        return ANALYSIS_STATS_LIMIT

    def shutdown(self):
        # We have no way of knowing which worker to be shut down here
        # This is a no-op since the PluginRunner already shuts the plugins down
        pass
