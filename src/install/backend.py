import importlib
import logging
import os
import stat
import subprocess
from contextlib import suppress
from pathlib import Path
from subprocess import PIPE, STDOUT

import distro

import config
from compile_yara_signatures import main as compile_signatures
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.install import (
    InstallationError,
    OperateInDirectory,
    apt_install_packages,
    dnf_install_packages,
    install_pip_packages,
    read_package_list_from_file,
)
from helperFunctions.yara import compile_plugin_yara_signatures

BIN_DIR = Path(__file__).parent.parent / 'bin'
INSTALL_DIR = Path(__file__).parent
PIP_DEPENDENCIES = INSTALL_DIR / 'requirements_backend.txt'


def main(skip_docker):
    if distro.id() != 'fedora':
        pkgs = read_package_list_from_file(INSTALL_DIR / 'apt-pkgs-backend.txt')
        apt_install_packages(*pkgs)
    else:
        pkgs = read_package_list_from_file(INSTALL_DIR / 'dnf-pkgs-backend.txt')
        dnf_install_packages(*pkgs)

    install_pip_packages(PIP_DEPENDENCIES)

    _install_checksec()

    if not skip_docker:
        _install_docker_images()

    # install plug-in dependencies
    _install_plugins(skip_docker)

    # create directories
    _create_firmware_directory()

    # compiling yara signatures
    compile_signatures()
    # compile yara test signatures
    compile_plugin_yara_signatures(
        Path(__file__).parent.parent / 'test/unit/analysis/test.yara',
        Path(__file__).parent.parent / 'analysis/signatures',
    )

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_backend').unlink()
        Path('start_fact_backend').symlink_to('src/start_fact_backend.py')

    return 0


def _install_docker_images():
    # pull extraction docker container
    logging.info('Pulling fact extraction container')

    docker_process = subprocess.run(
        'docker pull fkiecad/fact_extractor', shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False
    )
    if docker_process.returncode != 0:
        raise InstallationError(f'Failed to pull extraction container:\n{docker_process.stdout}')


def install_plugin_docker_images():
    # Distribution can be None here since it will not be used for installing
    # docker images
    _install_plugins(skip_docker=False, only_docker=True)


def _create_firmware_directory():
    logging.info('Creating firmware directory')

    data_dir_name = config.backend.firmware_file_storage_directory
    mkdir_process = subprocess.run(
        f'sudo mkdir -p --mode=0744 {data_dir_name}', shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False
    )
    chown_process = subprocess.run(
        f'sudo chown {os.getuid()}:{os.getgid()} {data_dir_name}',
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        text=True,
        check=False,
    )
    if not all(code == 0 for code in (mkdir_process.returncode, chown_process.returncode)):
        raise InstallationError(
            f'Failed to create directories for binary storage\n{mkdir_process.stdout}\n{chown_process.stdout}'
        )


def _install_plugins(skip_docker, only_docker=False):
    installer_paths = Path(get_src_dir() + '/plugins/').glob('*/*/install.py')

    for install_script in installer_paths:
        plugin_name = install_script.parent.name
        plugin_type = install_script.parent.parent.name

        plugin = importlib.import_module(f'plugins.{plugin_type}.{plugin_name}.install')

        plugin_installer = plugin.Installer(skip_docker=skip_docker)
        logging.info(f'Installing {plugin_name} plugin.')
        if not only_docker:
            plugin_installer.install()
        else:
            with OperateInDirectory(plugin_installer.base_path):
                plugin_installer.install_docker_images()
        logging.info(f'Finished installing {plugin_name} plugin.\n')


def _install_checksec():
    checksec_path = BIN_DIR / 'checksec'

    logging.info('Installing checksec.sh')
    checksec_url = 'https://raw.githubusercontent.com/slimm609/checksec.sh/2.5.0/checksec'
    wget_process = subprocess.run(
        f'wget -P {BIN_DIR} {checksec_url}', shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False
    )
    if wget_process.returncode != 0:
        raise InstallationError(f'Error during installation of checksec.sh\n{wget_process.stdout}')
    checksec_path.chmod(checksec_path.stat().st_mode | stat.S_IEXEC)  # chmod +x
