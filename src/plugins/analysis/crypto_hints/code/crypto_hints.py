from __future__ import annotations

from typing import TYPE_CHECKING, List

import pydantic

from analysis.plugin import AnalysisPluginV0, addons, compat

if TYPE_CHECKING:
    import io


class AnalysisPlugin(AnalysisPluginV0, compat.AnalysisBasePluginAdapterMixin):
    class Schema(pydantic.BaseModel):
        matches: List[dict]

    def __init__(self):
        metadata = AnalysisPluginV0.MetaData(
            name='crypto_hints',
            description='find indicators of specific crypto algorithms',
            version='0.2.0',
            Schema=AnalysisPlugin.Schema,
        )
        super().__init__(metadata=metadata)

        self._yara = addons.Yara(plugin=self)

    def summarize(self, result):
        return [match['rule'] for match in result.matches]

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        return AnalysisPlugin.Schema(
            matches=[compat.yara_match_to_dict(m) for m in self._yara.match(file_handle)],
        )
