"""
REST endpoint for the ghidra_targeted_analysis plugin.

Registers:
    POST /plugins/ghidra_targeted_analysis/rest/<uid>

Request body (JSON)::

    {
        "entry_points":  ["main", "0x00401000"],   // required
        "sensitive_vars": ["argv", "buf"],           // optional
        "max_depth": 5                               // optional, default 5
    }

Successful response (HTTP 200)::

    {
        "status": 0,
        "result": {
            "entry_points": [...],
            "sensitive_vars": [...],
            "call_tree": [...]
        },
        "request": {"uid": "..."},
        ...
    }
"""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

from flask import request
from flask_restx import Namespace

import config
from analysis.plugin import AnalysisFailedError
from helperFunctions.uid import is_uid
from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

PLUGIN_NAME = 'ghidra_targeted_analysis'
_ENDPOINT = f'/plugins/{PLUGIN_NAME}/rest'

api = Namespace(_ENDPOINT)


@api.hide
class PluginRestRoutes(RestResourceBase):
    """REST resource for on-demand targeted Ghidra call-tree analysis."""

    ENDPOINTS = (  # noqa: RUF012
        (f'{_ENDPOINT}/<string:uid>', ['POST']),
    )

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def post(self, uid: str) -> tuple[dict, int]:
        """
        Trigger a targeted call-tree analysis for the file identified by *uid*.

        The binary file is located on disk using FACT's firmware storage layout
        (``firmware_file_storage_directory / uid[:2] / uid``).

        **Body parameters:**

        * ``entry_points`` *(list[str], required)* – Function names or
          ``0x``-prefixed addresses to use as call-tree roots.
        * ``sensitive_vars`` *(list[str], optional)* – Variable names whose
          presence in pseudocode should be highlighted.
        * ``max_depth`` *(int, optional, default 5)* – Maximum callee depth to
          explore.
        """
        endpoint = self.ENDPOINTS[0][0]
        request_data = {'uid': uid}

        # ----------------------------------------------------------------
        # Validate request body
        # ----------------------------------------------------------------
        body = request.json or {}
        entry_points: list[str] = body.get('entry_points', [])
        sensitive_vars: list[str] = body.get('sensitive_vars', [])
        try:
            max_depth = int(body.get('max_depth', 5))
        except (TypeError, ValueError):
            return error_message('max_depth must be an integer', endpoint, request_data)

        if not entry_points:
            return error_message(
                '"entry_points" must be a non-empty list of function names or addresses',
                endpoint,
                request_data,
            )

        # ----------------------------------------------------------------
        # Validate UID format (prevents path traversal)
        # ----------------------------------------------------------------
        if not is_uid(uid):
            return error_message(
                f'Invalid UID format: "{uid}"',
                endpoint,
                request_data,
                return_code=HTTPStatus.BAD_REQUEST,
            )

        # ----------------------------------------------------------------
        # Resolve binary path from UID
        # ----------------------------------------------------------------
        # Note: `uid` has already been validated by `is_uid()` which enforces
        # the pattern [a-f0-9]{64}_[0-9]+ — no path separators are possible.
        # The `relative_to()` check below is a defence-in-depth guard.
        storage_dir = Path(config.backend.firmware_file_storage_directory).resolve()
        candidate = (storage_dir / uid[:2] / uid).resolve()
        # Use relative_to() as a canonical confinement check – raises ValueError
        # if the resolved path escapes the storage directory.
        try:
            candidate.relative_to(storage_dir)
        except ValueError:
            return error_message(
                'Invalid UID: path escapes storage directory',
                endpoint,
                request_data,
                return_code=HTTPStatus.BAD_REQUEST,
            )
        file_path = candidate
        if not file_path.exists():
            return error_message(
                f'Binary file not found for UID "{uid}"',
                endpoint,
                request_data,
                return_code=HTTPStatus.NOT_FOUND,
            )

        # ----------------------------------------------------------------
        # Run analysis
        # ----------------------------------------------------------------
        # Import here to avoid circular imports at module load time.
        from plugins.analysis.ghidra_targeted_analysis.code.ghidra_targeted_analysis import (
            AnalysisPlugin,
        )

        plugin = AnalysisPlugin()
        try:
            result = plugin.run_targeted_analysis(
                str(file_path),
                entry_points=entry_points,
                sensitive_vars=sensitive_vars,
                max_depth=max_depth,
            )
        except AnalysisFailedError as exc:
            return error_message(
                str(exc),
                endpoint,
                request_data,
                return_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            )

        return success_message(
            {'result': result.model_dump()},
            endpoint,
            request_data,
        )
