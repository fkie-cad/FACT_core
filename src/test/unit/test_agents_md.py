"""Make sure that the paths referenced in the AGENTS.md files (instructions for coding agents) still exist."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from helperFunctions.fileSystem import get_src_dir

SRC_DIR = Path(get_src_dir())
REPO_ROOT = SRC_DIR.parent
# names in backticks that look like paths but aren't
NOT_A_PATH = {'fkiecad/fact_extractor'}
PATH_REGEX = re.compile(r'^[\w.*/-]+(:\w+)?$')
CODE_SPAN_REGEX = re.compile(r'`([^`]+)`')
CODE_BLOCK_REGEX = re.compile(r'^```.*?^```', flags=re.DOTALL | re.MULTILINE)


def _find_agents_md_files() -> list[Path]:
    result = [REPO_ROOT / 'AGENTS.md']
    for root, dirs, files in os.walk(SRC_DIR):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {'__pycache__', 'node_modules'}]
        if 'AGENTS.md' in files:
            result.append(Path(root) / 'AGENTS.md')
    return [file for file in result if file.is_file()]


def _is_path(text: str) -> bool:
    if text in NOT_A_PATH or text.startswith('/') or not PATH_REGEX.match(text):
        return False
    path = text.split(':', maxsplit=1)[0]
    return '/' in path or path.endswith(('.py', '.toml', '.md', '.ini'))


def _get_referenced_paths() -> list[tuple[Path, str]]:
    return [
        (file, match)
        for file in _find_agents_md_files()
        # code blocks are removed because their backticks would mess up the matching of code spans
        for match in sorted(set(CODE_SPAN_REGEX.findall(CODE_BLOCK_REGEX.sub('', file.read_text()))))
        if _is_path(match)
    ]


def _resolve(path: str, agents_md_dir: Path) -> list[Path]:
    # paths may be relative to the repo root, to `src/` or to the dir of the AGENTS.md file,
    # or refer to a subdirectory of the packages in it (e.g. `view/` of analysis plugins)
    pattern = path.rstrip('/')
    for base in (REPO_ROOT, SRC_DIR, agents_md_dir):
        if matches := list(base.glob(pattern)):
            return matches
    return list(agents_md_dir.glob(f'*/{pattern}'))


@pytest.mark.parametrize(
    ('agents_md', 'reference'),
    _get_referenced_paths(),
    ids=lambda value: str(value.relative_to(REPO_ROOT)) if isinstance(value, Path) else value,
)
def test_paths_in_agents_md_exist(agents_md: Path, reference: str):
    path, _, symbol = reference.partition(':')
    matches = _resolve(path, agents_md.parent)
    assert matches, f'{agents_md.relative_to(REPO_ROOT)}: `{reference}` does not exist (anymore)'
    if symbol:
        assert any(symbol in file.read_text() for file in matches if file.is_file()), (
            f'{agents_md.relative_to(REPO_ROOT)}: `{symbol}` not found in {path}'
        )
