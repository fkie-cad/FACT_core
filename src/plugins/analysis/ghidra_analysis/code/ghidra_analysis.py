"""
This plugin uses Ghidra to decompile binary files extracted from firmware images.
For each function it stores the decompiled pseudocode and the list of called functions
(call graph). This data can be used for further automated analysis.

Ghidra is run in headless mode inside a Docker container.  The container receives
the binary via a bind-mount, runs a custom Ghidra script that emits a JSON result
file, and the plugin then parses that result.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from subprocess import CompletedProcess
from typing import TYPE_CHECKING, List

from docker.types import Mount
from pydantic import BaseModel
from requests import RequestException
from semver import Version

import config
from analysis.plugin import AnalysisFailedError, AnalysisPluginV0
from helperFunctions.docker import run_docker_container

if TYPE_CHECKING:
    from io import FileIO

DOCKER_IMAGE = 'ghidra-fact:latest'
GHIDRA_SCRIPTS_DIR = str(Path(__file__).parent.parent / 'ghidra_scripts')

# Maximum number of characters kept per function's pseudocode to avoid
# storing excessively large blobs in the database.
DEFAULT_MAX_PSEUDOCODE_LENGTH = 10_000


class FunctionInfo(BaseModel):
    name: str
    address: str
    pseudocode: str
    callees: List[str]


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        functions: List[FunctionInfo]

    def __init__(self):
        super().__init__(
            metadata=self.MetaData(
                name='ghidra_analysis',
                description=(
                    'Decompiles binary files using Ghidra and stores the resulting pseudocode '
                    'together with the call graph (callee list per function) for further analysis.'
                ),
                dependencies=['file_type'],
                mime_whitelist=[
                    'application/x-executable',
                    'application/x-pie-executable',
                    'application/x-sharedlib',
                ],
                version=Version(1, 0, 0),
                Schema=self.Schema,
                timeout=600,
            )
        )
        plugin_cfg = config.backend.plugin.get(self.metadata.name, None)
        self.max_pseudocode_length: int = getattr(plugin_cfg, 'max_pseudocode_length', DEFAULT_MAX_PSEUDOCODE_LENGTH)

    # ------------------------------------------------------------------
    # Docker helpers
    # ------------------------------------------------------------------

    def _run_ghidra_in_docker(self, file_path: str, output_dir: str) -> CompletedProcess:
        """Run Ghidra headless analyser in a Docker container.

        *file_path* is mounted read-only as ``/input`` inside the container.
        *output_dir* is mounted as ``/output`` so the Java script can write
        ``result.json`` there.  The Ghidra scripts directory is mounted as
        ``/scripts``.
        """
        command = (
            '/opt/ghidra/support/analyzeHeadless /tmp/ghidra_proj TmpProject'
            ' -import /input'
            ' -postScript DecompileAndCallGraph.java /output/result.json'
            ' -scriptPath /scripts'
            ' -deleteProject'
            ' -noanalysis'
        )
        try:
            result = run_docker_container(
                DOCKER_IMAGE,
                combine_stderr_stdout=True,
                timeout=self.metadata.timeout - 30,
                command=command,
                mounts=[
                    Mount('/input', file_path, type='bind', read_only=True),
                    Mount('/output', output_dir, type='bind'),
                    Mount('/scripts', GHIDRA_SCRIPTS_DIR, type='bind', read_only=True),
                ],
            )
        except RequestException as exc:
            raise AnalysisFailedError(
                'No response from Ghidra Docker container (possible timeout)'
            ) from exc
        return result

    # ------------------------------------------------------------------
    # Result parsing
    # ------------------------------------------------------------------

    def _parse_ghidra_output(self, result_json: str) -> list[FunctionInfo]:
        try:
            data = json.loads(result_json)
        except json.JSONDecodeError as exc:
            raise AnalysisFailedError('Could not parse Ghidra result JSON') from exc

        functions = []
        for func in data.get('functions', []):
            pseudocode = func.get('pseudocode', '')
            if len(pseudocode) > self.max_pseudocode_length:
                pseudocode = pseudocode[: self.max_pseudocode_length] + '\n/* [truncated] */'
            functions.append(
                FunctionInfo(
                    name=func.get('name', '<unknown>'),
                    address=func.get('address', '0x0'),
                    pseudocode=pseudocode,
                    callees=func.get('callees', []),
                )
            )
        return functions

    # ------------------------------------------------------------------
    # Plugin interface
    # ------------------------------------------------------------------

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict) -> Schema:
        """Decompile the binary with Ghidra and return pseudocode + call graph."""
        del virtual_file_path, analyses

        file_path = os.path.realpath(file_handle.name)

        with tempfile.TemporaryDirectory(prefix='fact-ghidra-') as output_dir:
            self._run_ghidra_in_docker(file_path, output_dir)

            result_path = Path(output_dir) / 'result.json'
            if not result_path.exists():
                logging.error(
                    '[ghidra_analysis] result.json not found. Ghidra may have failed silently.'
                )
                raise AnalysisFailedError('Ghidra did not produce a result file (see logs for details)')

            result_json = result_path.read_text(encoding='utf-8')

        functions = self._parse_ghidra_output(result_json)
        return self.Schema(functions=functions)

    def summarize(self, result: Schema) -> list[str]:
        """Return the list of decompiled function names as a summary."""
        return [f.name for f in result.functions] if result else []
