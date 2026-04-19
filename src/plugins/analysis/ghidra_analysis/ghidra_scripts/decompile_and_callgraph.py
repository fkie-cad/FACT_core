#!/usr/bin/env python3
"""
Ghidra analysis script using the pyghidra Python bridge.

Decompiles every non-external, non-thunk function in the target binary and
collects the callee list (call graph) for each function.  Results are written
as a JSON file so the FACT plugin can read them from a Docker bind-mount.

Usage:
    python3 decompile_and_callgraph.py <binary_path> <output_json_path>
"""

from __future__ import annotations

import json
import sys


def _build_function_map(program, monitor):
    """Return a mapping of function name and address string → Function object."""
    func_map = {}
    for func in program.getListing().getFunctions(True):
        func_map[func.getName()] = func
        raw = func.getEntryPoint().toString()
        addr = raw if raw.startswith('0x') else '0x' + raw
        func_map[addr] = func
    return func_map


def _decompile_function(decompiler, func, monitor):
    """Return decompiled C pseudocode for *func*, or an empty string on failure."""
    try:
        result = decompiler.decompileFunction(func, 60, monitor)
        if result and result.decompileCompleted():
            return result.getDecompiledFunction().getC() or ''
    except Exception:  # noqa: BLE001
        pass
    return ''


def _get_callees(func, monitor):
    """Return a list of callee names for *func*."""
    try:
        return [callee.getName() for callee in func.getCalledFunctions(monitor)]
    except Exception:  # noqa: BLE001
        return []


def analyze(binary_path: str, output_path: str) -> None:
    import pyghidra  # imported inside the function to keep the top-level importable in tests

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

        functions = []
        for func in program.getListing().getFunctions(True):
            if func.isExternal() or func.isThunk():
                continue

            raw = func.getEntryPoint().toString()
            address = raw if raw.startswith('0x') else '0x' + raw

            functions.append(
                {
                    'name': func.getName(),
                    'address': address,
                    'pseudocode': _decompile_function(decompiler, func, monitor),
                    'callees': _get_callees(func, monitor),
                }
            )

        decompiler.dispose()

    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump({'functions': functions}, fh)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: decompile_and_callgraph.py <binary> <output.json>', file=sys.stderr)
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2])
