import logging
import os
import re
import shutil
import subprocess
from contextlib import suppress
from pathlib import Path
from shlex import split
from subprocess import PIPE, STDOUT

from packaging.version import parse as parse_version

import config
from helperFunctions.install import (
    InstallationError,
    OperateInDirectory,
    apt_install_packages,
    dnf_install_packages,
    install_pip_packages,
    is_virtualenv,
    read_package_list_from_file,
    run_cmd_with_logging,
)
from storage.graphql.util import get_env

DEFAULT_CERT = '.\n.\n.\n.\n.\nexample.com\n.\n\n\n'
INSTALL_DIR = Path(__file__).parent
PIP_DEPENDENCIES = INSTALL_DIR / 'requirements_frontend.txt'
STATIC_WEB_DIR = INSTALL_DIR.parent / 'web_interface' / 'static'
MIME_ICON_DIR = STATIC_WEB_DIR / 'file_icons'
ICON_THEME_INSTALL_PATH = Path('/usr/share/icons/Papirus/24x24')
NODEENV_DIR = 'nodeenv'


def execute_commands_and_raise_on_return_code(commands, error=None):
    for command in commands:
        bad_return = error if error else f'execute {command}'
        cmd_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False)
        if cmd_process.returncode != 0:
            raise InstallationError(f'Failed to {bad_return}\n{cmd_process.stdout}')


def _create_directory_for_authentication():
    logging.info('Creating directory for authentication')

    dburi = config.frontend.authentication.user_database

    factauthdir = '/'.join(dburi.split('/')[:-1])[10:]  # FIXME this should be beautified with pathlib

    mkdir_process = subprocess.run(
        f'sudo mkdir -p --mode=0744 {factauthdir}', shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False
    )
    chown_process = subprocess.run(
        f'sudo chown {os.getuid()}:{os.getgid()} {factauthdir}',
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        text=True,
        check=False,
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
    nginx_process = subprocess.run('sudo nginx -s reload', shell=True, capture_output=True, text=True, check=False)
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
            '(cd ../web_interface/templates/ '
            '&& sudo ln -s $PWD/maintenance.html /etc/nginx/error/maintenance.html) || true',
        ],
        error='configuring nginx',
    )


def _install_docker_images(radare):
    if radare:
        logging.info('Initializing docker container for radare')

        with OperateInDirectory('radare'):
            docker_compose_process = subprocess.run(
                'docker compose build', shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False
            )
            if docker_compose_process.returncode != 0:
                raise InstallationError(f'Failed to initialize radare container:\n{docker_compose_process.stdout}')

    # pull pdf report container
    logging.info('Pulling pdf report container')
    docker_process = subprocess.run(
        'docker pull fkiecad/fact_pdf_report', shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False
    )
    if docker_process.returncode != 0:
        raise InstallationError(f'Failed to pull pdf report container:\n{docker_process.stdout}')


def _copy_mime_icons():
    # copy mime icons to the static folder so that they can be used by the web server
    for source, target in [
        ('mimetypes', 'mimetypes'),
        ('devices/audio-card.svg', 'firmware.svg'),
        ('devices/media-floppy.svg', 'filesystem.svg'),
        ('places/folder-brown.svg', 'folder.svg'),
        ('status/dialog-error.svg', 'not_analyzed.svg'),
        ('emblems/emblem-symbolic-link.svg', 'mimetypes/inode-symlink.svg'),
        ('apps/tux.svg', 'linux.svg'),
    ]:
        run_cmd_with_logging(f'cp -rL {ICON_THEME_INSTALL_PATH / source} {MIME_ICON_DIR / target}')


def _install_nodejs(nodejs_version: str = '22'):
    latest_version = _find_latest_node_version(nodejs_version)
    with OperateInDirectory(STATIC_WEB_DIR):
        if Path(NODEENV_DIR).is_dir() and not _node_version_is_up_to_date(latest_version):
            shutil.rmtree(NODEENV_DIR)

        if Path(NODEENV_DIR).is_dir():
            logging.info('Skipping nodeenv installation (already exists)')
        else:
            run_cmd_with_logging(f'nodeenv {NODEENV_DIR} --node={latest_version} --prebuilt')
        run_cmd_with_logging(f'. {NODEENV_DIR}/bin/activate && npm install --no-fund .', shell=True)


def _find_latest_node_version(target_version: str) -> str:
    proc = subprocess.run(split('nodeenv --list'), capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise InstallationError('nodejs installation failed. Is nodeenv installed?')
    available_versions = [
        parse_version(v) for v in re.split(r'[\n\t ]', proc.stderr) if v and v.startswith(target_version)
    ]
    if not available_versions:
        raise InstallationError(f'No nodejs installation candidates found for version "{target_version}"')
    return str(max(available_versions))


def _node_version_is_up_to_date(nodejs_version: str) -> bool:
    try:
        proc = subprocess.run(split('./nodeenv/bin/node --version'), capture_output=True, text=True, check=True)
        installed_version = proc.stdout.strip().lstrip('v')
        return installed_version == nodejs_version
    except (subprocess.CalledProcessError, OSError):  # venv dir exists but node is not installed correctly
        return False


def _init_hasura():
    with OperateInDirectory(INSTALL_DIR.parent / 'storage' / 'graphql' / 'hasura'):
        run_cmd_with_logging('docker compose up -d', env=get_env())
        run_cmd_with_logging('python3 init_hasura.py')


def main(skip_docker, radare, nginx, distribution, skip_hasura):
    if distribution != 'fedora':
        pkgs = read_package_list_from_file(INSTALL_DIR / 'apt-pkgs-frontend.txt')
        apt_install_packages(*pkgs)
    else:
        pkgs = read_package_list_from_file(INSTALL_DIR / 'dnf-pkgs-frontend.txt')
        dnf_install_packages(*pkgs)

    # flask-security is not maintained anymore and replaced by flask-security-too.
    # Since python package naming conflicts are not resolved automatically, we remove flask-security manually.
    pip = 'pip' if is_virtualenv() else 'sudo -EH pip3'
    run_cmd_with_logging(f'{pip} uninstall -y flask-security')

    install_pip_packages(PIP_DEPENDENCIES)

    _install_nodejs()

    # create user database
    _create_directory_for_authentication()

    if nginx:
        _install_nginx(distribution)

    if not skip_docker:
        _install_docker_images(radare)

    if not skip_hasura:
        _init_hasura()

    if not MIME_ICON_DIR.is_dir():
        MIME_ICON_DIR.mkdir()
        _copy_mime_icons()

    with OperateInDirectory(INSTALL_DIR.parent.parent):
        with suppress(FileNotFoundError):
            Path('start_fact_frontend').unlink()
        Path('start_fact_frontend').symlink_to('src/start_fact_frontend.py')

    return 0
