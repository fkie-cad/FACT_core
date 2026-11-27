import subprocess
from types import SimpleNamespace

import pytest

from storage.graphql import util
from storage.graphql.hasura.init_hasura import HasuraSetup
from storage.graphql.util import get_env, update_hasura_containers

LOCAL_DB = {'server': 'localhost', 'database': 'some_db', 'rw_user': 'rw', 'rw_pw': 'secret'}
REMOTE_DB = {'server': '10.0.0.5', 'port': 5433, 'database': 'some_db', 'rw_user': 'rw', 'rw_pw': 'secret'}


@pytest.mark.common_config_overwrite({'postgres': LOCAL_DB})
def test_get_env_local_db():
    env = get_env()
    assert env['FACT_DB_URL'] == 'postgresql://rw:secret@/some_db?host=/var/run/postgresql'
    assert env['DB_LOCALITY'] == 'local'


@pytest.mark.common_config_overwrite({'postgres': REMOTE_DB})
def test_get_env_remote_db():
    env = get_env()
    assert env['FACT_DB_URL'] == 'postgresql://rw:secret@10.0.0.5:5433/some_db'
    assert env['DB_LOCALITY'] == 'remote'


@pytest.mark.common_config_overwrite(
    {'postgres': {'server': '10.0.0.5', 'port': 5433, 'test_database': 'test_db', 'ro_user': 'ro', 'ro_pw': 'pw'}}
)
def test_hasura_test_db_url_uses_config():
    assert HasuraSetup(testing=True)._get_db_url() == 'postgresql://ro:pw@10.0.0.5:5433/test_db'


class MockRun:
    def __init__(self, ps_output: str = '', error: Exception | None = None):
        self.ps_output = ps_output
        self.error = error
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if self.error:
            raise self.error
        return SimpleNamespace(stdout=self.ps_output if 'ps' in command else '')


@pytest.mark.common_config_overwrite({'postgres': REMOTE_DB})
def test_update_hasura_containers(monkeypatch):
    mock_run = MockRun(ps_output='0123456789ab\n')
    monkeypatch.setattr(util.subprocess, 'run', mock_run)
    update_hasura_containers()

    assert [command for command, _ in mock_run.calls] == [
        ['docker', 'compose', 'ps', '--all', '--quiet'],
        ['docker', 'compose', 'up', '--detach'],
    ]
    _, kwargs = mock_run.calls[-1]
    assert kwargs['cwd'] == util.HASURA_DIR
    assert kwargs['env']['FACT_DB_URL'] == 'postgresql://rw:secret@10.0.0.5:5433/some_db'


def test_update_hasura_containers_not_installed(monkeypatch):
    mock_run = MockRun(ps_output='')
    monkeypatch.setattr(util.subprocess, 'run', mock_run)
    update_hasura_containers()

    assert len(mock_run.calls) == 1, 'Hasura must not be started if it was not set up'


@pytest.mark.parametrize(
    'error',
    [FileNotFoundError('docker'), subprocess.CalledProcessError(1, 'docker', output='daemon not running')],
)
def test_update_hasura_containers_error(monkeypatch, caplog, error):
    monkeypatch.setattr(util.subprocess, 'run', MockRun(error=error))
    update_hasura_containers()

    assert 'Could not update the Hasura containers' in caplog.text
