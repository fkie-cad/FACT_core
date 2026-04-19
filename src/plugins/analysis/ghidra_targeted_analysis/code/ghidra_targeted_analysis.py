"""
Ghidra targeted analysis plugin.

Unlike :mod:`ghidra_analysis` which decompiles *all* functions in a binary,
this plugin performs a *targeted* call-tree analysis starting from one or
more user-supplied entry points.  For each function in the call tree it
collects:

* Decompiled C pseudocode (via Ghidra's ``DecompInterface``).
* The direct callee list.
* References to user-supplied *sensitive variables* found in the pseudocode.

The standard ``analyze()`` method is intentionally a no-op (it returns an
empty :class:`Schema`).  Actual analysis is triggered on-demand via the
plugin's REST endpoint:

    ``POST /plugins/ghidra_targeted_analysis/rest/<uid>``

with a JSON body::

    {
        "entry_points":  ["main", "0x00401000"],
        "sensitive_vars": ["argv", "buf", "password"],
        "max_depth": 5
    }

The response contains the full ``Schema`` in JSON form.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from subprocess import CompletedProcess
from typing import TYPE_CHECKING, Dict, List, Optional

from docker.types import Mount
from pydantic import BaseModel, Field
from requests import RequestException
from semver import Version

import config
from analysis.plugin import AnalysisFailedError, AnalysisPluginV0
from helperFunctions.docker import run_docker_container

if TYPE_CHECKING:
    from io import FileIO

PLUGIN_NAME = 'ghidra_targeted_analysis'
DOCKER_IMAGE = 'ghidra-fact:latest'
GHIDRA_SCRIPTS_DIR = str(Path(__file__).parent.parent / 'ghidra_scripts')

DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_PSEUDOCODE_LENGTH = 10_000


# ---------------------------------------------------------------------------
# Schema models
# ---------------------------------------------------------------------------


class FunctionDetail(BaseModel):
    """Detailed information about a single function in the call tree."""

    #: Demangled function name.
    name: str
    #: Entry-point address as a ``0x``-prefixed hex string.
    address: str
    #: Decompiled C pseudocode (may be empty for external/thunk functions).
    pseudocode: str
    #: Names of directly called functions.
    callees: List[str]
    #: Depth in the call tree relative to the entry point (entry point = 0).
    depth: int
    #: Subset of ``sensitive_vars`` that appear literally in the pseudocode.
    sensitive_var_refs: List[str]


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        #: Entry-point names / addresses supplied by the user.
        entry_points: List[str] = Field(default_factory=list)
        #: Sensitive variable names supplied by the user.
        sensitive_vars: List[str] = Field(default_factory=list)
        #: All functions discovered in the call tree (BFS order).
        call_tree: List[FunctionDetail] = Field(default_factory=list)

    def __init__(self):
        super().__init__(
            metadata=self.MetaData(
                name=PLUGIN_NAME,
                description=(
                    'Performs a targeted Ghidra call-tree analysis starting from user-supplied '
                    'entry points.  For each function in the call tree the decompiled pseudocode, '
                    'callee list and references to sensitive variables are collected.  '
                    'Trigger analysis via POST /plugins/ghidra_targeted_analysis/rest/<uid>.'
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
        plugin_cfg = config.backend.plugin.get(PLUGIN_NAME, None)
        self.max_pseudocode_length: int = getattr(
            plugin_cfg, 'max_pseudocode_length', DEFAULT_MAX_PSEUDOCODE_LENGTH
        )

    # ------------------------------------------------------------------
    # Standard plugin interface (no-op – analysis is user-triggered)
    # ------------------------------------------------------------------

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict) -> Schema:
        """Return an empty schema.

        Targeted analysis is not triggered automatically.  Use the REST
        endpoint ``POST /plugins/ghidra_targeted_analysis/rest/<uid>``
        instead.
        """
        del file_handle, virtual_file_path, analyses
        return self.Schema()

    def summarize(self, result: Schema) -> list[str]:
        return [f.name for f in result.call_tree] if result and result.call_tree else []

    # ------------------------------------------------------------------
    # Docker execution
    # ------------------------------------------------------------------

    def _run_targeted_analysis_in_docker(
        self,
        file_path: str,
        output_dir: str,
        entry_points: list[str],
        sensitive_vars: list[str],
        max_depth: int,
    ) -> CompletedProcess:
        """Run the targeted pyghidra script in Docker.

        Parameters are passed via a JSON config file written into *output_dir*
        (mounted as ``/output`` inside the container) to avoid shell-escaping
        issues with complex argument values.
        """
        # Write analysis parameters to a file in the shared output directory
        config_path = Path(output_dir) / 'config.json'
        config_path.write_text(
            json.dumps(
                {
                    'entry_points': entry_points,
                    'sensitive_vars': sensitive_vars,
                    'max_depth': max_depth,
                }
            ),
            encoding='utf-8',
        )

        command = 'python3 /scripts/targeted_analysis.py /input /output/config.json /output/result.json'
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
    # Public targeted-analysis API (called from the routes module)
    # ------------------------------------------------------------------

    def run_targeted_analysis(
        self,
        file_path: str,
        entry_points: list[str],
        sensitive_vars: list[str],
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> Schema:
        """Run targeted analysis and return a populated :class:`Schema`.

        This is the method invoked by the REST endpoint.

        :param file_path: Absolute path to the binary on the host filesystem.
        :param entry_points: Function names or ``0x``-prefixed addresses to
            use as call-tree roots.
        :param sensitive_vars: Variable names whose presence in pseudocode
            should be highlighted.
        :param max_depth: Maximum callee depth to explore (default 5).
        :raises AnalysisFailedError: If Ghidra fails or produces no output.
        """
        file_path = os.path.realpath(file_path)

        with tempfile.TemporaryDirectory(prefix='fact-ghidra-targeted-') as output_dir:
            self._run_targeted_analysis_in_docker(
                file_path, output_dir, entry_points, sensitive_vars, max_depth
            )

            result_path = Path(output_dir) / 'result.json'
            if not result_path.exists():
                logging.error(
                    '[ghidra_targeted_analysis] result.json not found. '
                    'Ghidra may have failed silently.'
                )
                raise AnalysisFailedError(
                    'Ghidra targeted analysis did not produce a result file (see logs for details)'
                )

            result_json = result_path.read_text(encoding='utf-8')

        return self._parse_result(result_json, entry_points, sensitive_vars)

    # ------------------------------------------------------------------
    # Result parsing
    # ------------------------------------------------------------------

    def _parse_result(
        self,
        result_json: str,
        entry_points: list[str],
        sensitive_vars: list[str],
    ) -> Schema:
        try:
            data = json.loads(result_json)
        except json.JSONDecodeError as exc:
            raise AnalysisFailedError(
                'Could not parse Ghidra targeted analysis result JSON'
            ) from exc

        call_tree = []
        for func in data.get('call_tree', []):
            pseudocode = func.get('pseudocode', '')
            if len(pseudocode) > self.max_pseudocode_length:
                pseudocode = pseudocode[: self.max_pseudocode_length] + '\n/* [truncated] */'
            call_tree.append(
                FunctionDetail(
                    name=func.get('name', '<unknown>'),
                    address=func.get('address', '0x0'),
                    pseudocode=pseudocode,
                    callees=func.get('callees', []),
                    depth=func.get('depth', 0),
                    sensitive_var_refs=func.get('sensitive_var_refs', []),
                )
            )

        return self.Schema(
            entry_points=data.get('entry_points', entry_points),
            sensitive_vars=data.get('sensitive_vars', sensitive_vars),
            call_tree=call_tree,
        )
