import os
import sys
from pathlib import Path
from shlex import split
from subprocess import PIPE, STDOUT, Popen

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn

try:
    import config
    from helperFunctions.install import OperateInDirectory
except ImportError:
    SRC_DIR = Path(__file__).parent.parent.parent
    sys.path.append(str(SRC_DIR))
    import config
    from helperFunctions.install import OperateInDirectory

progress = Progress(
    BarColumn(),
    TaskProgressColumn(),
    SpinnerColumn(),
)


def restart():
    user = config.common.postgres.rw_user
    pw = config.common.postgres.rw_pw
    port = config.common.postgres.port
    server = config.common.postgres.server
    if server in ('localhost', '127.0.0.1', '::1'):
        server = 'host.docker.internal'
    env = {
        **os.environ,
        'HASURA_ADMIN_SECRET': config.frontend.hasura.admin_secret,
        'FACT_DB_URL': f'postgresql://{user}:{pw}@{server}:{port}/fact_db',
        'HASURA_PORT': str(config.frontend.hasura.port),
    }

    with OperateInDirectory(Path(__file__).parent), progress:
        progress.console.print('Restarting Hasura ⏳')
        for command in progress.track(('docker compose down', 'docker compose up -d')):
            progress.console.print(f'Running {command} ...')
            process = Popen(split(command), stdout=PIPE, stderr=STDOUT, text=True, env=env)
            while not process.poll():
                if output := process.stdout.readline():
                    progress.console.print(f'\t{output.strip()}')
                else:
                    break
            process.wait()
        progress.console.print('Finished restarting Hasura ✨')


if __name__ == '__main__':
    config.load()
    restart()
