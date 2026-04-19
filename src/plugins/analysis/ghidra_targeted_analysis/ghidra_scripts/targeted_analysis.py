#!/usr/bin/env python3
"""
Targeted Ghidra analysis script using the pyghidra Python bridge.

Performs a breadth-first traversal of the call graph starting from one or
more user-supplied entry points.  For every function encountered up to
``max_depth`` levels deep the script:

1. Decompiles the function to C pseudocode.
2. Identifies which of the user-supplied *sensitive variables* appear
   literally in the pseudocode.
3. Collects the direct callee list.

Results are written as a JSON file so the FACT plugin can read them from
the Docker bind-mount.

Usage:
    python3 targeted_analysis.py <binary_path> <config_json_path> <output_json_path>

Config JSON format (read from ``config_json_path``)::

    {
        "entry_points":  ["main", "0x00401000"],
        "sensitive_vars": ["argv", "buf", "password"],
        "max_depth": 5
    }

Output JSON format::

    {
        "entry_points":  ["main"],
        "sensitive_vars": ["buf"],
        "call_tree": [
            {
                "name": "main",
                "address": "0x00401000",
                "pseudocode": "int main(...) { ... }",
                "callees": ["gets", "printf"],
                "depth": 0,
                "sensitive_var_refs": ["buf"]
            },
            ...
        ]
    }
"""

from __future__ import annotations

import json
import sys
from collections import deque


def _find_sensitive_refs(pseudocode: str, sensitive_vars: list[str]) -> list[str]:
    """Return which *sensitive_vars* appear as substrings in *pseudocode*."""
    return [v for v in sensitive_vars if v in pseudocode]


def _normalize_address(raw: str) -> str:
    return raw if raw.startswith('0x') else '0x' + raw


def _build_func_lookup(program) -> dict:
    """Build a dict mapping function name and address string → Function object."""
    lookup: dict = {}
    for func in program.getListing().getFunctions(True):
        lookup[func.getName()] = func
        addr = _normalize_address(func.getEntryPoint().toString())
        lookup[addr] = func
    return lookup


def _decompile(decompiler, func, monitor) -> str:
    try:
        res = decompiler.decompileFunction(func, 60, monitor)
        if res and res.decompileCompleted():
            return res.getDecompiledFunction().getC() or ''
    except Exception:  # noqa: BLE001
        pass
    return ''


def _get_callees(func, monitor) -> list[str]:
    try:
        return [c.getName() for c in func.getCalledFunctions(monitor)]
    except Exception:  # noqa: BLE001
        return []


def analyze(binary_path: str, config_path: str, output_path: str) -> None:
    with open(config_path, encoding='utf-8') as fh:
        cfg = json.load(fh)

    entry_points: list[str] = cfg.get('entry_points', [])
    sensitive_vars: list[str] = cfg.get('sensitive_vars', [])
    max_depth: int = int(cfg.get('max_depth', 5))

    import pyghidra  # imported here to keep module importable without pyghidra installed

    with pyghidra.open_program(
        binary_path,
        project_location='/tmp/ghidra_proj',
        project_name='TmpProject',
    ) as flat_api:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore[import]
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]

        program = flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()

        decompiler = DecompInterface()
        decompiler.setOptions(DecompileOptions())
        decompiler.openProgram(program)

        func_lookup = _build_func_lookup(program)

        # BFS from each entry point
        queue: deque[tuple[object, int]] = deque()
        for ep in entry_points:
            func = func_lookup.get(ep)
            if func is not None:
                queue.append((func, 0))

        visited: dict[str, dict] = {}  # func_name → result dict

        while queue:
            func, depth = queue.popleft()
            name = func.getName()

            if name in visited or depth > max_depth:
                continue

            addr = _normalize_address(func.getEntryPoint().toString())
            pseudocode = '' if func.isExternal() or func.isThunk() else _decompile(decompiler, func, monitor)
            callees = _get_callees(func, monitor)
            sensitive_refs = _find_sensitive_refs(pseudocode, sensitive_vars)

            visited[name] = {
                'name': name,
                'address': addr,
                'pseudocode': pseudocode,
                'callees': callees,
                'depth': depth,
                'sensitive_var_refs': sensitive_refs,
            }

            # Enqueue direct callees for the next BFS level
            for callee_name in callees:
                if callee_name not in visited:
                    callee_func = func_lookup.get(callee_name)
                    if callee_func is not None:
                        queue.append((callee_func, depth + 1))

        decompiler.dispose()

    result = {
        'entry_points': entry_points,
        'sensitive_vars': sensitive_vars,
        'call_tree': list(visited.values()),
    }

    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump(result, fh)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(
            'Usage: targeted_analysis.py <binary> <config.json> <output.json>',
            file=sys.stderr,
        )
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2], sys.argv[3])
