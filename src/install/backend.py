import logging
import os
import stat
from contextlib import suppress
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code
from compile_yara_signatures import main as compile_signatures

from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_install_packages, check_string_in_command_output, dnf_install_packages,
    load_main_config, pip3_install_packages
)

BIN_DIR = Path(__file__).parent.parent / 'bin'


def main(skip_docker, distribution):

    # dependencies
    if distribution == 'fedora':
        dnf_install_packages('libjpeg-devel', 'openssl-devel', 'python3-tkinter')
    else:
        apt_install_packages('libjpeg-dev', 'libssl-dev', 'python3-tk')

    pip3_install_packages('pluginbase', 'Pillow', 'cryptography', 'pyopenssl', 'matplotlib', 'docker', 'networkx')

    # install yara
    _install_yara(distribution)

    # install checksec.sh
    _install_checksec(distribution)

    # installing common code modules
    pip3_install_packages('git+https://github.com/fkie-cad/common_helper_yara.git')
    pip3_install_packages('git+https://github.com/mass-project/common_analysis_base.git')

    if not skip_docker:
        _install_docker_images()
        _install_plugin_docker_images()

    # install plug-in dependencies
    _install_plugins(distribution)

    # configure environment
    _edit_environment()

    # create directories
    _create_firmware_directory()

    # compiling yara signatures
    compile_signatures()
    _, yarac_return = execute_shell_command_get_return_code('yarac -d test_flag=false ../test/unit/analysis/test.yara ../analysis/signatures/Yara_Base_Plugin.yc')
    if yarac_return != 0:
        raise InstallationError('Failed to compile yara test signatures')

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_backend').unlink()
        Path('start_fact_backend').symlink_to('src/start_fact_backend.py')

    return 0


def _install_docker_images():
    # pull extraction docker container
    logging.info('Pulling fact extraction container')

    output, return_code = execute_shell_command_get_return_code('docker pull fkiecad/fact_extractor')
    if return_code != 0:
        raise InstallationError(f'Failed to pull extraction container:\n{output}')


def _install_plugin_docker_images():
    logging.info('Installing plugin docker dependecies')
    find_output, return_code = execute_shell_command_get_return_code('find ../plugins -iname "install_docker.sh"')
    if return_code != 0:
        raise InstallationError('Error retrieving plugin docker installation scripts')
    for install_script in find_output.splitlines(keepends=False):
        logging.info('Running {}'.format(install_script))
        shell_output, return_code = execute_shell_command_get_return_code(f'{install_script}')
        if return_code != 0:
            raise InstallationError(
                f'Error in installation of {Path(install_script).parent.name} plugin docker images docker images\n{shell_output}')


def _edit_environment():
    logging.info('set environment variables...')
    for command in ['sudo cp -f fact_env.sh /etc/profile.d/', 'sudo chmod 755 /etc/profile.d/fact_env.sh', '. /etc/profile']:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError(f'Failed to add environment changes [{command}]\n{output}')


def _create_firmware_directory():
    logging.info('Creating firmware directory')

    config = load_main_config()
    data_dir_name = config.get('data_storage', 'firmware_file_storage_directory')
    mkdir_output, mkdir_code = execute_shell_command_get_return_code(f'sudo mkdir -p --mode=0744 {data_dir_name}')
    chown_output, chown_code = execute_shell_command_get_return_code(f'sudo chown {os.getuid()}:{os.getgid()} {data_dir_name}')
    if not all(code == 0 for code in (mkdir_code, chown_code)):
        raise InstallationError(f'Failed to create directories for binary storage\n{mkdir_output}\n{chown_output}')


def _install_plugins(distribution):
    logging.info('Installing plugins')
    find_output, return_code = execute_shell_command_get_return_code('find ../plugins -iname "install.sh"')
    if return_code != 0:
        raise InstallationError('Error retrieving plugin installation scripts')
    for install_script in find_output.splitlines(keepends=False):
        logging.info('Running {}'.format(install_script))
        shell_output, return_code = execute_shell_command_get_return_code(f'{install_script} {distribution}')
        if return_code != 0:
            raise InstallationError(
                f'Error in installation of {Path(install_script).parent.name} plugin\n{shell_output}')


def _install_yara(distribution):  # pylint: disable=too-complex
    logging.info('Installing yara')

    # CAUTION: Yara python binding is installed in install/common.py, because it is needed in the frontend as well.

    if distribution != 'fedora':
        apt_install_packages('bison', 'flex')

    if check_string_in_command_output('yara --version', '3.7.1'):
        logging.info('skipping yara installation (already installed)')
        return

    wget_output, wget_code = execute_shell_command_get_return_code('wget https://github.com/VirusTotal/yara/archive/v3.7.1.zip')
    if wget_code != 0:
        raise InstallationError(f'Error on yara download.\n{wget_output}')
    zip_output, return_code = execute_shell_command_get_return_code('unzip v3.7.1.zip')
    Path('v3.7.1.zip').unlink()
    if return_code != 0:
        raise InstallationError(f'Error on yara extraction.\n{zip_output}')
    yara_folder = [child for child in Path('.').iterdir() if 'yara-3.' in child.name][0]
    with OperateInDirectory(yara_folder.name, remove=True):
        os.chmod('bootstrap.sh', 0o775)
        for command in ['./bootstrap.sh', './configure --enable-magic', 'make -j$(nproc)', 'sudo make install']:
            output, return_code = execute_shell_command_get_return_code(command)
            if return_code != 0:
                raise InstallationError(f'Error in yara installation.\n{output}')


def _install_checksec(distribution):
    checksec_path = BIN_DIR / 'checksec'
    if checksec_path.is_file():
        logging.info('Skipping checksec.sh installation (already installed)')
        return

    # dependencies
    install_function = apt_install_packages if distribution != 'fedora' else dnf_install_packages
    install_function('binutils', 'openssl', 'file')

    logging.info('Installing checksec.sh')
    checksec_url = "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec"
    output, return_code = execute_shell_command_get_return_code(f'wget -P {BIN_DIR} {checksec_url}')
    if return_code != 0:
        raise InstallationError(f'Error during installation of checksec.sh\n{output}')
    checksec_path.chmod(checksec_path.stat().st_mode | stat.S_IEXEC)  # chmod +x
