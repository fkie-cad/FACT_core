import yara

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
        return self.metadata.timeout

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


def yara_match_to_dict(match: yara.Match) -> dict:
    """Converts a ``yara.Match`` to the format that :py:class:`analysis.YaraPluginBase` would return."""
    # FIXME (yara): Use this when we upgrade to yara-python 4.3.0
    # strings = []
    # for string_match in match.strings:
    #    for string_instance in string_match.instances:
    #        strings.append((string_instance.offset, string_match.identifier, string_instance.matched_data.hex()))

    strings = []
    for offset, identifier, data in match.strings:
        strings.append((offset, identifier, data.hex()))

    return {
        'meta': {
            # Optional
            'date': match.meta.get('date'),
            # Optional
            'author': match.meta.get('author'),
            'description': match.meta['description'],
        },
        'rule': match.rule,
        'strings': strings,
    }
