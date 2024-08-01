import gc
import os
import subprocess
from subprocess import PIPE, STDOUT

import pytest

import fact.init_postgres
import fact.update_statistic
from fact.helperFunctions.fileSystem import get_src_dir


@pytest.mark.parametrize(
    ('script', 'expected_str'),
    [
        ('start_fact.py', 'FACT Starter'),
        ('start_fact_backend.py', 'FACT Backend'),
        ('start_fact_frontend.py', 'FACT Frontend'),
        ('start_fact_database.py', 'FACT DB-Service'),
    ],
)
def test_start_script_help_and_version(script, expected_str):
    cmd_process = subprocess.run(
        f'{os.path.join(get_src_dir(), script)} -h',  # noqa: PTH118
        timeout=5,
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        text=True,
        check=False,
    )
    assert cmd_process.returncode == 0
    assert f'usage: {script}' in cmd_process.stdout

    cmd_process = subprocess.run(
        f'{os.path.join(get_src_dir(), script)} -V',  # noqa: PTH118
        timeout=5,
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        text=True,
        check=False,
    )
    assert expected_str in cmd_process.stdout, f'Wrong output {cmd_process.stdout}'
    assert cmd_process.returncode == 0

    gc.collect()


@pytest.mark.parametrize('script', [fact.update_statistic, fact.init_postgres])
def test_start_scripts_with_main(script):
    assert script.main([script.__name__, '-t']) == 0, 'script did not run successfully'
    gc.collect()


@pytest.mark.skip(reason='Not working in CI')
def test_fact_complete_start():
    cmd_process = subprocess.run(
        f"{os.path.join(get_src_dir(), 'start_fact.py')} -d -t",  # noqa: PTH118
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        text=True,
        check=False,
    )
    assert '[DEBUG]' in cmd_process.stdout
    assert 'Analysis System online...' in cmd_process.stdout
    assert 'Analysis System offline' in cmd_process.stdout
    assert cmd_process.returncode == 0

    gc.collect()
