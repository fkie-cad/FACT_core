import logging
from contextlib import suppress
from pathlib import Path

from common_helper_process import execute_shell_command, execute_shell_command_get_return_code

from helperFunctions.install import InstallationError, OperateInDirectory

CODENAME_TRANSLATION = {
    'tara': 'bionic', 'tessa': 'bionic', 'tina': 'bionic', 'tricia': 'bionic',
    'ulyana': 'focal', 'ulyssa': 'focal', 'uma': 'focal', 'una': 'focal',
}


def install_postgres():
    codename = execute_shell_command('lsb_release -cs').rstrip()
    codename = CODENAME_TRANSLATION.get(codename, codename)
    # based on https://www.postgresql.org/download/linux/ubuntu/
    command_list = [
        f'sudo sh -c \'echo "deb http://apt.postgresql.org/pub/repos/apt {codename}-pgdg main" > /etc/apt/sources.list.d/pgdg.list\'',
        'wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -',
        'sudo apt-get update',
        'sudo apt-get -y install postgresql-14'
    ]
    for command in command_list:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError(f'Failed to set up PostgreSQL: {output}')


def main():
    logging.info('Setting up PostgreSQL database')
    install_postgres()
    # delay import so that sqlalchemy is installed
    from install.init_postgres import main as init_postgres  # pylint: disable=import-outside-toplevel
    init_postgres()

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_db').unlink()
        Path('start_fact_db').symlink_to('src/start_fact_db.py')

    return 0
