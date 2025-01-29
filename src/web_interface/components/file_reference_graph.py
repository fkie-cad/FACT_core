from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from web_interface.components.dependency_graph import DepGraphData

EXECUTABLE_MIMES = {
    'application/x-executable',
    'application/x-pie-executable',
    'application/x-sharedlib',
}


def get_edges_and_nodes(data_by_path: dict[str, DepGraphData]) -> tuple[set[tuple[str, str]], set[str]]:
    edges = set()
    nodes = set()
    home_path = _find_probable_home_dir(data_by_path.keys())
    for path, item in data_by_path.items():
        if not item.libraries:
            continue
        for referenced_file in item.libraries:
            dereferenced_path = resolve_relative_path(path, referenced_file, home_path)
            if dereferenced_path in data_by_path:
                if _is_probably_linking_dependency(item, data_by_path[dereferenced_path]):
                    continue  # we are not interested in ELF dependencies here
                edges.add((path, dereferenced_path))
                nodes.update({path, dereferenced_path})
    return edges, nodes


def _is_probably_linking_dependency(source_data: DepGraphData, target_data: DepGraphData) -> bool:
    return source_data.mime in EXECUTABLE_MIMES and (
        target_data.mime == 'application/x-sharedlib'
        or (target_data.mime == 'inode/symlink' and '.so' in target_data.full_type)
    )


def _find_probable_home_dir(paths: Iterable[str]) -> Path:
    for path in paths:
        if path.startswith('/home/') and path.count('/') >= 3:  # noqa: PLR2004
            return list(Path(path).parents)[-3]
    return Path('/root')  # best guess


def resolve_relative_path(source_file: str, target_file: str, home_path: Path) -> str:
    if target_file.startswith('.'):
        return os.path.normpath(Path(source_file).parent / target_file)
    if target_file.startswith('~/'):
        return str(home_path / target_file[2:])
    if '..' in target_file:
        return os.path.normpath(target_file)
    return target_file
