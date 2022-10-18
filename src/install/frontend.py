import logging
import os
import subprocess
from contextlib import suppress
from pathlib import Path
from subprocess import PIPE, STDOUT

from config import cfg, load_config
from helperFunctions.install import (
    InstallationError,
    OperateInDirectory,
    apt_install_packages,
    dnf_install_packages,
    install_pip_packages,
    read_package_list_from_file,
    run_cmd_with_logging,
)

load_config()

DEFAULT_CERT = '.\n.\n.\n.\n.\nexample.com\n.\n\n\n'
INSTALL_DIR = Path(__file__).parent
PIP_DEPENDENCIES = INSTALL_DIR / 'requirements_frontend.txt'


def execute_commands_and_raise_on_return_code(commands, error=None):  # pylint: disable=invalid-name
    for command in commands:
        bad_return = error if error else f'execute {command}'
        cmd_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, text=True)
        if cmd_process.returncode != 0:
            raise InstallationError(f'Failed to {bad_return}\n{cmd_process.stdout}')


def _create_directory_for_authentication():  # pylint: disable=invalid-name
    logging.info('Creating directory for authentication')

    dburi = cfg.data_storage.user_database
    # pylint: disable=fixme
    factauthdir = '/'.join(dburi.split('/')[:-1])[10:]  # FIXME this should be beautified with pathlib

    mkdir_process = subprocess.run(
        f'sudo mkdir -p --mode=0744 {factauthdir}', shell=True, stdout=PIPE, stderr=STDOUT, text=True
    )
    chown_process = subprocess.run(
        f'sudo chown {os.getuid()}:{os.getgid()} {factauthdir}', shell=True, stdout=PIPE, stderr=STDOUT, text=True
    )

    if not all(return_code == 0 for return_code in [mkdir_process.returncode, chown_process.returncode]):
        raise InstallationError(
            'Error in creating directory for authentication database.\n{}'.format(
                '\n'.join((mkdir_process.stdout, mkdir_process.stdout))
            )
        )


def _install_nginx(distribution):
    if distribution != 'fedora':
        apt_install_packages('nginx')
    else:
        dnf_install_packages('nginx')
    _generate_and_install_certificate()
    _configure_nginx()
    if distribution == 'fedora':
        execute_commands_and_raise_on_return_code(
            [
                'sudo restorecon -v /etc/nginx/fact.*',
                'sudo semanage fcontext -at httpd_log_t "/var/log/fact(/.*)?" || true',
                'sudo restorecon -v -R /var/log/fact',
            ],
            error='restore selinux context',
        )
    nginx_process = subprocess.run('sudo nginx -s reload', shell=True, capture_output=True, text=True)
    if nginx_process.returncode != 0:
        raise InstallationError(f'Failed to start nginx\n{nginx_process.stderr}')


def _generate_and_install_certificate():
    logging.info('Generating self-signed certificate')
    execute_commands_and_raise_on_return_code(
        [
            'openssl genrsa -out fact.key 4096',
            f'echo "{DEFAULT_CERT}" | openssl req -new -key fact.key -out fact.csr',
            'openssl x509 -req -days 730 -in fact.csr -signkey fact.key -out fact.crt',
            'sudo mv fact.key fact.csr fact.crt /etc/nginx',
        ],
        error='generate SSL certificate',
    )


def _configure_nginx():
    logging.info('Configuring nginx')
    execute_commands_and_raise_on_return_code(
        [
            'sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak',
            'sudo rm /etc/nginx/nginx.conf',
            # copy is better on redhat to respect selinux context
            '(cd ../config && sudo install -m 644 $PWD/nginx.conf /etc/nginx/nginx.conf)',
            '(sudo mkdir /etc/nginx/error || true)',
            '(cd ../web_interface/templates/ && sudo ln -s $PWD/maintenance.html /etc/nginx/error/maintenance.html) || true',
        ],
        error='configuring nginx',
    )


def _install_docker_images(radare):
    if radare:
        logging.info('Initializing docker container for radare')

        with OperateInDirectory('radare'):
            docker_compose_process = subprocess.run(
                'docker-compose build', shell=True, stdout=PIPE, stderr=STDOUT, text=True
            )
            if docker_compose_process.returncode != 0:
                raise InstallationError(f'Failed to initialize radare container:\n{docker_compose_process.stdout}')

    # pull pdf report container
    logging.info('Pulling pdf report container')
    docker_process = subprocess.run(
        'docker pull fkiecad/fact_pdf_report', shell=True, stdout=PIPE, stderr=STDOUT, text=True
    )
    if docker_process.returncode != 0:
        raise InstallationError(f'Failed to pull pdf report container:\n{docker_process.stdout}')


def main(skip_docker, radare, nginx, distribution):
    if distribution != 'fedora':
        pkgs = read_package_list_from_file(INSTALL_DIR / 'apt-pkgs-frontend.txt')
        apt_install_packages(*pkgs)
    else:
        pkgs = read_package_list_from_file(INSTALL_DIR / 'dnf-pkgs-frontend.txt')
        dnf_install_packages(*pkgs)

    # flask-security is not maintained anymore and replaced by flask-security-too.
    # Since python package naming conflicts are not resolved automatically, we remove flask-security manually.
    run_cmd_with_logging('sudo -EH pip3 uninstall -y flask-security')
    install_pip_packages(PIP_DEPENDENCIES)

    # npm does not allow us to install packages to a specific directory
    with OperateInDirectory("../../src/web_interface/static"):
        # EBADENGINE can probably be ignored because we probably don't need node.
        run_cmd_with_logging('npm install --no-fund .')

    # create user database
    _create_directory_for_authentication()

    if nginx:
        _install_nginx(distribution)

    if not skip_docker:
        _install_docker_images(radare)

    with OperateInDirectory(INSTALL_DIR.parent.parent):
        with suppress(FileNotFoundError):
            Path('start_fact_frontend').unlink()
        Path('start_fact_frontend').symlink_to('src/start_fact_frontend.py')

    return 0
