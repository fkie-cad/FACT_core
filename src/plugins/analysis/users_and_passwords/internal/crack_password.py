from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from tempfile import NamedTemporaryFile

from docker.types import Mount

from helperFunctions.docker import run_docker_container

JOHN_POT = Path(__file__).parent.parent / 'bin' / 'john.pot'
RESULTS_DELIMITER = '=== Results: ==='


def crack_hash(passwd_entry: bytes, format_term: str = '') -> tuple[str | None, str | None]:
    with NamedTemporaryFile() as fp:
        fp.write(passwd_entry)
        fp.seek(0)
        john_process = run_docker_container(
            'fact/john:alpine-3.18',
            command=f'/work/input_file {format_term}',
            mounts=[
                Mount('/work/input_file', fp.name, type='bind'),
                Mount('/root/.john/john.pot', str(JOHN_POT), type='bind'),
            ],
            logging_label='users_and_passwords',
        )
        if 'No password hashes loaded' in john_process.stdout:
            return None, 'hash type is not supported'
        output = _parse_john_output(john_process.stdout)
    if output:
        if any('0 password hashes cracked' in line for line in output):
            return None, 'password cracking not successful'
        with suppress(IndexError):
            return output[0].split(':')[1], None
    return None, None


def _parse_john_output(john_output: str) -> list[str]:
    if RESULTS_DELIMITER in john_output:
        start_offset = john_output.find(RESULTS_DELIMITER) + len(RESULTS_DELIMITER) + 1  # +1 is '\n' after delimiter
        return [line for line in john_output[start_offset:].split('\n') if line]
    return []
