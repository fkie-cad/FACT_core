from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydantic import BaseModel
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0
from plugins.analysis.binary_forensics.internal.binwalk import BinwalkSignatureResult, get_binwalk_signature_analysis
from plugins.analysis.binary_forensics.internal.entropy import Entropy, get_entropy_analysis
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED

if TYPE_CHECKING:
    from io import FileIO


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        entropy: Entropy
        file_matches: list[BinwalkSignatureResult]

    def __init__(self):
        super().__init__(
            metadata=AnalysisPluginV0.MetaData(
                name='binary_forensics',
                description='binary forensic analysis (entropy and Binwalk file signatures)',
                version=Version(1, 0, 0),
                Schema=self.Schema,
                mime_blacklist=['audio/', 'image/', 'video/', 'text/', *MIME_BLACKLIST_COMPRESSED],
            ),
        )
        self.thresholds = {
            'very high entropy': self._get_plugin_cfg_entry('very_high_entropy_threshold', 0.95),
            'high entropy': self._get_plugin_cfg_entry('high_entropy_threshold', 0.8),
            'medium high entropy': self._get_plugin_cfg_entry('medium_high_entropy_threshold', 0.6),
            'medium entropy': self._get_plugin_cfg_entry('medium_entropy_threshold', 0.4),
            'medium low entropy': self._get_plugin_cfg_entry('medium_low_entropy_threshold', 0.2),
            'low entropy': self._get_plugin_cfg_entry('low_entropy_threshold', 0.05),
        }

    def _get_plugin_cfg_entry(self, name: str, default: float) -> float:
        entry = getattr(config.backend.plugin.get(self.metadata.name, {}), name, default)
        try:
            return float(entry)
        except (TypeError, ValueError):
            logging.warning(f'Failed to parse config entry {name} of plugin {self.metadata.name} (should be float)')
            return default

    def analyze(self, file_handle: FileIO, virtual_file_path: dict[str, list[str]], analyses: dict) -> Schema:
        del virtual_file_path, analyses

        return self.Schema(
            entropy=get_entropy_analysis(file_handle),
            file_matches=get_binwalk_signature_analysis(file_handle, timeout=self.metadata.timeout),
        )

    def summarize(self, result: Schema) -> list:
        return [*self._summarize_entropy(result.entropy), *self._summarize_binwalk_result(result.file_matches)]

    def _summarize_entropy(self, result: Entropy) -> list[str]:
        for key, value in self.thresholds.items():
            if result.avg_entropy > value:
                return [key]
        return ['very low entropy']

    @staticmethod
    def _summarize_binwalk_result(binwalk_result: list[BinwalkSignatureResult]) -> list[str]:
        summary = []
        for item in binwalk_result:
            summary.append(item.name)
        return summary
