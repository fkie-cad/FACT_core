import gc
import os
import subprocess
from subprocess import PIPE, STDOUT

import pytest

import init_postgres
import update_statistic
from helperFunctions.fileSystem import get_src_dir


@pytest.mark.parametrize(
    'script, expected_str',
    [
        ('start_fact.py', 'FACT Starter'),
        ('start_fact_backend.py', 'FACT Backend'),
        ('start_fact_frontend.py', 'FACT Frontend'),
        ('start_fact_db.py', 'FACT DB-Service'),
    ],
)
def test_start_script_help_and_version(script, expected_str):
    cmd_process = subprocess.run(
        f'{os.path.join(get_src_dir(), script)} -h',
        timeout=5,
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        universal_newlines=True,
    )
    assert cmd_process.returncode == 0
    assert f'usage: {script}' in cmd_process.stdout

    cmd_process = subprocess.run(
        f'{os.path.join(get_src_dir(), script)} -V',
        timeout=5,
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        universal_newlines=True,
    )
    assert expected_str in cmd_process.stdout, f'Wrong output {cmd_process.stdout}'
    assert cmd_process.returncode == 0

    gc.collect()


@pytest.mark.parametrize('script', [update_statistic, init_postgres])
def test_start_scripts_with_main(script):
    assert script.main([script.__name__, '-t']) == 0, 'script did not run successfully'
    gc.collect()


@pytest.mark.skip(reason='Not working in CI')
def test_fact_complete_start():
    cmd_process = subprocess.run(
        f"{os.path.join(get_src_dir(), 'start_fact.py')} -d -t",
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        universal_newlines=True,
    )
    assert '[DEBUG]' in cmd_process.stdout
    assert 'Analysis System online...' in cmd_process.stdout
    assert 'Analysis System offline' in cmd_process.stdout
    assert cmd_process.returncode == 0

    gc.collect()
