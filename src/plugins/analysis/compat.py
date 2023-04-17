from statistic.analysis_stats import ANALYSIS_STATS_LIMIT


class AnalysisBasePluginAdapterMixin:
    """A mixin that makes PluginV0 ompatible to AnalysisBasePlugin"""

    # pylint: disable=invalid-name

    def start(self):
        # This is a no-op
        pass

    @property
    def FILE(self):  # noqa: N802
        # What is this even used for?
        raise NotImplementedError

    @property
    def NAME(self):  # noqa: N802
        return self.metadata.name

    @property
    def DESCRIPTION(self):  # noqa: N802
        return self.metadata.description

    @property
    def DEPENDENCIES(self):  # noqa: N802
        return self.metadata.dependencies

    @property
    def VERSION(self):  # noqa: N802
        return self.metadata.version

    @property
    def RECURSIVE(self):  # noqa: N802
        return False

    @property
    def TIMEOUT(self):  # noqa: N802
        return self.metadata.timeout

    @property
    def SYSTEM_VERSION(self):  # noqa: N802
        return self.metadata.version

    @property
    def MIME_BLACKLIST(self):  # noqa: N802
        return self.metadata.mime_blacklist

    @property
    def MIME_WHITELIST(self):  # noqa: N802
        return self.metadata.mime_whitelist

    @property
    def ANALYSIS_STATS_LIMIT(self):  # noqa: N802
        # Since no plugin sets this, we just use the default from AnalysisBasePlugin here
        return ANALYSIS_STATS_LIMIT

    def shutdown(self):
        # We have no way of knowing which worker to be shut down here
        # This is a no-op since the PluginRunner already shuts the plugins down
        pass
