from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import psutil
import yara
from more_itertools import batched
from pydantic import BaseModel
from yara import Rules

from helperFunctions.fileSystem import get_src_dir

if TYPE_CHECKING:
    from collections.abc import Iterator

SIGNATURE_DIR = Path(get_src_dir()) / 'analysis/signatures'


class StringInstance(BaseModel):
    matched_data: bytes
    offset: int
    matched_length: int


class StringMatch(BaseModel):
    identifier: str
    instances: list[StringInstance]

    @classmethod
    def from_yara_string(cls, yara_string: yara.StringMatch) -> StringMatch:
        return cls(
            identifier=yara_string.identifier,
            instances=[
                StringInstance(
                    matched_data=inst.matched_data,
                    offset=inst.offset,
                    matched_length=inst.matched_length,
                )
                for inst in yara_string.instances
            ],
        )


class Match(BaseModel):
    rule: str
    meta: dict[str, Any]
    strings: list[StringMatch]
    file: str

    @classmethod
    def from_yara_match(cls, match: yara.Match, file: str) -> Match:
        return cls(
            rule=match.rule,
            meta=match.meta,
            strings=[StringMatch.from_yara_string(s) for s in match.strings],
            file=file,
        )


def compile_rules(source: str | Path, target: str | Path, external_variables: dict[str, str] | None = None) -> None:
    """
    Compile YARA rules from a source file or directory and store as a compiled YARA rules file.

    :param source: Path to the source YARA file or directory containing YARA files.
    :param target: Path to the output compiled YARA file (.yc).
    :param external_variables: Optional dictionary of external variables to pass during compilation.
    """
    source_path = Path(source)
    target_path = Path(target)

    rule_source = _concat_yara_files_from_dir(source_path) if source_path.is_dir() else source_path.read_text()
    rules = yara.compile(source=rule_source, externals=external_variables or {})
    rules.save(str(target_path))


def _concat_yara_files_from_dir(source_path: Path) -> str:
    all_rules = []
    for signature_file in sorted(source_path.iterdir()):
        if is_valid_yara_source_file(signature_file):
            all_rules.append(signature_file.read_text())
    return '\n'.join(all_rules)


def is_valid_yara_source_file(file: Path) -> bool:
    """
    Check if a file is a valid YARA rules file. Only works with uncompiled rules!

    :param file: Path to the source YARA file.
    :return: True if it is a valid YARA rules file, False otherwise.
    """
    try:
        yara.compile(filepath=str(file))
        return True
    except yara.Error:
        return False


def scan_file(rule_file: Path, target_file: Path) -> Iterator[Match]:
    """
    Scan a target file with compiled YARA rules.

    :param rule_file: Path to the compiled YARA file.
    :param target_file: Path to the file to scan.
    :return: List of Match objects.
    """
    rules = _load_rules(rule_file)
    for match in rules.match(str(target_file)):
        yield Match.from_yara_match(match, str(target_file))


def _load_rules(rule_file: Path) -> yara.Rules:
    try:
        return yara.load(str(rule_file))
    except yara.Error:
        return yara.compile(str(rule_file))


_ctx = SimpleNamespace(rules=None)


def _init_worker(rules_bytes: bytes) -> None:
    _ctx.rules = yara.load(file=BytesIO(rules_bytes))


def _scan_file(file: str) -> list[Match]:
    return [Match.from_yara_match(m, file) for m in _ctx.rules.match(file)]


def _scan_files_batch(files: list[str]) -> list[Match]:
    return [match for f in files for match in _scan_file(f)]


def scan_dir(
    rule_file: Path,
    target_dir: Path,
    threads: int = psutil.cpu_count(logical=False) or 4,
    batch_size: int = 128,
) -> list[Match]:
    """
    Scan directory recursively with YARA rules. Sadly, yara-python does not offer an API for this.

    :param rule_file: Path to the YARA rule file.
    :param target_dir: Path to the directory to scan.
    :param threads: The number of threads to use.
    :param batch_size: The batch size to use per thread.
    :return: List of matched strings.
    """
    files = [str(f) for f in target_dir.glob('**/*') if f.is_file()]
    return scan_files(rule_file, files, threads, batch_size)


def scan_files(
    rule_file: Path,
    target_files: list[str],
    threads: int = psutil.cpu_count(logical=False) or 4,
    batch_size: int = 128,
) -> list[Match]:
    """
    Scan directory recursively with YARA rules. Sadly, yara-python does not offer an API for this.

    :param rule_file: Path to the YARA rule file.
    :param target_files: Paths of the target files to scan.
    :param threads: The number of threads to use.
    :param batch_size: The batch size to use per thread.
    :return: List of matched strings.
    """
    rules = _load_rules(rule_file)
    rules_bytes = _get_compiled_rules_string(rules)

    matches = []
    with ProcessPoolExecutor(
        max_workers=threads,
        initializer=_init_worker,
        initargs=(rules_bytes,),
    ) as executor:
        for result in executor.map(_scan_files_batch, batched(target_files, batch_size)):
            matches.extend(result)

    return matches


def _get_compiled_rules_string(rules: Rules) -> bytes:
    buff = BytesIO()
    rules.save(file=buff)
    return buff.getvalue()


def get_all_matched_strings(matches: list[Match]) -> list[str]:
    """
    Extract all matched strings from a list of YARA match objects.

    :param matches: List of YARA Match objects.
    :return: List of matched strings.
    """
    matched_strings = []
    for match in matches:
        for string in match.strings:
            for instance in string.instances:
                matched_strings.append(instance.matched_data.decode('utf-8', errors='replace'))
    return matched_strings


def compile_signatures_of_plugin(
    signature_dir: Path, output_dir: Path = SIGNATURE_DIR, external_variables: dict | None = None
) -> None:
    """
    Compile YARA signatures from the signature directory of a plugin and put them in the rule directory.

    :param signature_dir: Path to the plugin's signature directory.
    :param output_dir: Path to the directory where the compiled YARA file will be saved.
    :param external_variables: Optional dictionary of external variables to pass during compilation.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    plugin_name = signature_dir.parent.name
    target_file = output_dir / f'{plugin_name}.yc'
    compile_rules(signature_dir, target_file, external_variables)
