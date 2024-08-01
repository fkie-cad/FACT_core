import yara

from fact.statistic.analysis_stats import ANALYSIS_STATS_LIMIT


class AnalysisBasePluginAdapterMixin:
    """A mixin that makes AnalysisPluginV0 compatible to AnalysisBasePlugin"""

    def start(self):
        # This is a no-op
        pass

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
        return str(self.metadata.version)

    @property
    def RECURSIVE(self):  # noqa: N802
        return False

    @property
    def TIMEOUT(self):  # noqa: N802
        return self.metadata.timeout

    @property
    def SYSTEM_VERSION(self):  # noqa: N802
        return self.metadata.system_version

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
        # The shutdown of plugin workers is handled by the PluginRunner
        pass


def yara_match_to_dict(match: yara.Match) -> dict:
    """Converts a ``yara.Match`` to the format that :py:class:`analysis.YaraPluginBase` would return."""
    # see YARA docs: https://yara.readthedocs.io/en/latest/yarapython.html#yara.StringMatchInstance
    strings = [
        (string_instance.offset, string_match.identifier, string_instance.matched_data.decode(errors='replace'))
        for string_match in match.strings  # type: yara.StringMatch
        for string_instance in string_match.instances  # type: yara.StringMatchInstance
    ]

    return {
        'meta': {
            key: match.meta.get(key)
            for key in ('open_source', 'software_name', 'website', 'date', 'author', 'description')
        },
        'rule': match.rule,
        'strings': strings,
    }
