from common_helper_process import execute_shell_command_get_return_code
import pytest
import os
import gc

from helperFunctions.fileSystem import get_src_dir


@pytest.mark.parametrize('script', [
    ('start_fact.py'),
    ('start_fact_backend.py'),
    ('start_fact_frontend.py'),
    ('start_fact_db.py'),
    ('update_statistic.py'),
    ('update_variety_data.py'),
    ('migrate_database.py'),
    ('init_database.py')
])
def test_start_script_help_and_version(script):
    output, return_code = execute_shell_command_get_return_code('{} -h'.format(os.path.join(get_src_dir(), script)), timeout=5)
    assert return_code == 0
    assert 'usage: {}'.format(script) in output

    output, return_code = execute_shell_command_get_return_code('{} -V'.format(os.path.join(get_src_dir(), script)), timeout=5)
    assert output[0:5] == 'FACT '
    assert return_code == 0

    gc.collect()


@pytest.mark.skip(reason="Not working in CI")
def test_fact_complete_start():
    output, return_code = execute_shell_command_get_return_code('{} -d -t'.format(os.path.join(get_src_dir(), 'start_fact.py')))
    assert '[DEBUG]' in output
    assert 'Analysis System online...' in output
    assert 'Analysis System offline' in output
    assert return_code == 0

    gc.collect()
