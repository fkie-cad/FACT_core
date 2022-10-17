import importlib
import logging
import os
import stat
import subprocess
from contextlib import suppress
from pathlib import Path
from subprocess import PIPE, STDOUT

import requests

from compile_yara_signatures import main as compile_signatures
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_install_packages, dnf_install_packages, install_pip_packages,
    load_main_config, read_package_list_from_file
)

BIN_DIR = Path(__file__).parent.parent / 'bin'
INSTALL_DIR = Path(__file__).parent
PIP_DEPENDENCIES = INSTALL_DIR / 'requirements_backend.txt'


def main(skip_docker, distribution):
    if distribution != 'fedora':
        pkgs = read_package_list_from_file(INSTALL_DIR / 'apt-pkgs-backend.txt')
        apt_install_packages(*pkgs)
    else:
        pkgs = read_package_list_from_file(INSTALL_DIR / 'dnf-pkgs-backend.txt')
        dnf_install_packages(*pkgs)

    install_pip_packages(PIP_DEPENDENCIES)

    # install yara
    _install_yara()

    _install_checksec()

    if not skip_docker:
        _install_docker_images()

    # install plug-in dependencies
    _install_plugins(distribution, skip_docker)

    # create directories
    _create_firmware_directory()

    # compiling yara signatures
    compile_signatures()
    yarac_process = subprocess.run(
        'yarac -d test_flag=false ../test/unit/analysis/test.yara ../analysis/signatures/Yara_Base_Plugin.yc',
        shell=True,
        stdout=PIPE,
        stderr=PIPE,
        universal_newlines=True,
    )
    if yarac_process.returncode != 0:
        raise InstallationError('Failed to compile yara test signatures')

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_backend').unlink()
        Path('start_fact_backend').symlink_to('src/start_fact_backend.py')

    return 0


def _install_docker_images():
    # pull extraction docker container
    logging.info('Pulling fact extraction container')

    docker_process = subprocess.run('docker pull fkiecad/fact_extractor', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    if docker_process.returncode != 0:
        raise InstallationError(f'Failed to pull extraction container:\n{docker_process.stdout}')


def install_plugin_docker_images():
    # Distribution can be None here since it will not be used for installing
    # docker images
    _install_plugins(None, skip_docker=False, only_docker=True)


def _create_firmware_directory():
    logging.info('Creating firmware directory')

    config = load_main_config()
    data_dir_name = config.get('data-storage', 'firmware-file-storage-directory')
    mkdir_process = subprocess.run(f'sudo mkdir -p --mode=0744 {data_dir_name}', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    chown_process = subprocess.run(f'sudo chown {os.getuid()}:{os.getgid()} {data_dir_name}', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    if not all(code == 0 for code in (mkdir_process.returncode, chown_process.returncode)):
        raise InstallationError(f'Failed to create directories for binary storage\n{mkdir_process.stdout}\n{chown_process.stdout}')


def _install_plugins(distribution, skip_docker, only_docker=False):
    installer_paths = Path(get_src_dir() + '/plugins/').glob('*/*/install.py')

    for install_script in installer_paths:
        plugin_name = install_script.parent.name
        plugin_type = install_script.parent.parent.name

        plugin = importlib.import_module(f'plugins.{plugin_type}.{plugin_name}.install')

        plugin_installer = plugin.Installer(distribution, skip_docker=skip_docker)
        logging.info(f'Installing {plugin_name} plugin.')
        if not only_docker:
            plugin_installer.install()
        else:
            plugin_installer.install_docker_images()
        logging.info(f'Finished installing {plugin_name} plugin.\n')


def _install_yara():  # pylint: disable=too-complex

    # CAUTION: Yara python binding is installed in install/common.py, because it is needed in the frontend as well.

    try:
        latest_url = requests.get('https://github.com/VirusTotal/yara/releases/latest').url
        latest_version = latest_url.split('/tag/')[1]
    except (AttributeError, KeyError):
        raise InstallationError('Could not find latest yara version') from None

    yara_process = subprocess.run('yara --version', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    if yara_process.returncode == 0 and yara_process.stdout.strip() == latest_version.strip('v'):
        logging.info('Skipping yara installation: Already installed and up to date')
        return

    logging.info(f'Installing yara {latest_version}')
    archive = f'{latest_version}.zip'
    download_url = f'https://github.com/VirusTotal/yara/archive/refs/tags/{archive}'
    wget_process = subprocess.run(f'wget {download_url}', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    if wget_process.returncode != 0:
        raise InstallationError(f'Error on yara download.\n{wget_process.stdout}')
    unzip_process = subprocess.run(f'unzip {archive}', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    Path(archive).unlink()
    if unzip_process.returncode != 0:
        raise InstallationError(f'Error on yara extraction.\n{unzip_process.stdout}')
    yara_folder = [p for p in Path('.').iterdir() if p.name.startswith('yara-')][0]
    with OperateInDirectory(yara_folder.name, remove=True):
        os.chmod('bootstrap.sh', 0o775)
        for command in ['./bootstrap.sh', './configure --enable-magic', 'make -j$(nproc)', 'sudo make install']:
            cmd_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
            if cmd_process.returncode != 0:
                raise InstallationError(f'Error in yara installation.\n{cmd_process.stdout}')


def _install_checksec():
    checksec_path = BIN_DIR / 'checksec'

    logging.info('Installing checksec.sh')
    checksec_url = 'https://raw.githubusercontent.com/slimm609/checksec.sh/2.5.0/checksec'
    wget_process = subprocess.run(f'wget -P {BIN_DIR} {checksec_url}', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    if wget_process.returncode != 0:
        raise InstallationError(f'Error during installation of checksec.sh\n{wget_process.stdout}')
    checksec_path.chmod(checksec_path.stat().st_mode | stat.S_IEXEC)  # chmod +x
