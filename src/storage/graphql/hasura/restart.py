#!/usr/bin/env python3
"""
This is a script for (re)starting Hasura (the GraphQL server which enables GraphQL Search in FACT).
It is necessary, because apart from running `docker compose up`, many environment variables need to be set (which
makes it almost infeasible to do this by hand). After starting, the Hasura web interface can be reached under the
address http://localhost:33333/ on the host system.
"""

import sys
from pathlib import Path
from shlex import split
from subprocess import PIPE, STDOUT, Popen

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn

try:
    import config
    from helperFunctions.install import OperateInDirectory
    from storage.graphql.util import get_env
except ImportError:
    SRC_DIR = Path(__file__).parent.parent.parent.parent
    sys.path.append(str(SRC_DIR))
    import config
    from helperFunctions.install import OperateInDirectory
    from storage.graphql.util import get_env

progress = Progress(
    BarColumn(),
    TaskProgressColumn(),
    SpinnerColumn(),
)


def restart():
    with OperateInDirectory(Path(__file__).parent), progress:
        progress.console.print('Restarting Hasura ⏳')
        for command in progress.track(('docker compose down', 'docker compose up -d')):
            progress.console.print(f'Running {command} ...')
            process = Popen(split(command), stdout=PIPE, stderr=STDOUT, text=True, env=get_env())
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
