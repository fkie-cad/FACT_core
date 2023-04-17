import io

import pydantic

import plugins.analysis.compat
from plugins import analysis
from plugins.analysis import addons


class AnalysisPlugin(analysis.PluginV0, analysis.compat.AnalysisBasePluginAdapterMixin):
    class Schema(pydantic.BaseModel):
        matches: list[dict]

    def __init__(self):
        metadata = analysis.PluginV0.MetaData(
            name='crypto_hints',
            description='find indicators of specific crypto algorithms',
            version='0.2.0',
            Schema=AnalysisPlugin.Schema,
        )
        super().__init__(metadata=metadata)

        self._yara = addons.Yara(plugin=self)

    def summarize(self, result):
        del result
        return []

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        return AnalysisPlugin.Schema(
            matches=[analysis.compat.yara_match_to_dict(m) for m in self._yara.match(file_handle)],
        )
