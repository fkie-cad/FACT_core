import logging
import os
from contextlib import suppress
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code
from compile_yara_signatures import main as compile_signatures
from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_install_packages,
    check_string_in_command, load_main_config, pip3_install_packages
)


def main():
    # dependencies
    apt_install_packages('python-dev', 'python-setuptools')
    apt_install_packages('libjpeg-dev')
    apt_install_packages('libssl-dev', 'python3-tk')
    pip3_install_packages('pluginbase', 'Pillow', 'cryptography', 'pyopenssl', 'entropy', 'matplotlib', 'docker')

    # install yara
    _install_yara()

    # build extraction docker container
    logging.info('Building fact extraction container')

    output, return_code = execute_shell_command_get_return_code('docker pull fkiecad/fact_extractor')
    if return_code != 0:
        raise InstallationError('Failed to pull extraction container:\n{}'.format(output))

    # installing common code modules
    pip3_install_packages('git+https://github.com/fkie-cad/common_helper_yara.git')
    pip3_install_packages('git+https://github.com/mass-project/common_analysis_base.git')

    # install plug-in dependencies
    _install_plugins()

    # configure environment
    _edit_sudoers()
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


def _edit_environment():
    logging.info('set environment variables...')
    for command in ['sudo cp -f fact_env.sh /etc/profile.d/', 'sudo chmod 755 /etc/profile.d/fact_env.sh', '. /etc/profile']:
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError('Failed to add environment changes [{}]\n{}'.format(command, output))


def _edit_sudoers():
    logging.info('add rules to sudo...')
    username = os.environ['USER']
    sudoers_content = '\n'.join(('{}\tALL=NOPASSWD: {}'.format(username, command) for command in (
        '/bin/mount', '/bin/umount', '/bin/chown'
    )))
    Path('/tmp/fact_overrides').write_text('{}\n'.format(sudoers_content))
    chown_output, chown_code = execute_shell_command_get_return_code('sudo chown root:root /tmp/fact_overrides')
    mv_output, mv_code = execute_shell_command_get_return_code('sudo mv /tmp/fact_overrides /etc/sudoers.d/fact_overrides')
    if not chown_code == mv_code == 0:
        raise InstallationError('Editing sudoers file did not succeed\n{}\n{}'.format(chown_output, mv_output))


def _create_firmware_directory():
    logging.info('Creating firmware directory')

    config = load_main_config()
    data_dir_name = config.get('data_storage', 'firmware_file_storage_directory')
    mkdir_output, mkdir_code = execute_shell_command_get_return_code('sudo mkdir -p --mode=0744 {}'.format(data_dir_name))
    chown_output, chown_code = execute_shell_command_get_return_code('sudo chown {}:{} {}'.format(os.getuid(), os.getgid(), data_dir_name))
    if not all(code == 0 for code in (mkdir_code, chown_code)):
        raise InstallationError('Failed to create directories for binary storage\n{}\n{}'.format(mkdir_output, chown_output))


def _install_plugins():
    logging.info('Installing plugins')
    find_output, return_code = execute_shell_command_get_return_code('find ../plugins -iname "install.sh"')
    if return_code != 0:
        raise InstallationError('Error retrieving plugin installation scripts')
    for install_script in find_output.splitlines(keepends=False):
        logging.info('Running {}'.format(install_script))
        shell_output, return_code = execute_shell_command_get_return_code(install_script)
        if return_code != 0:
            raise InstallationError('Error in installation of {} plugin\n{}'.format(Path(install_script).parent.name, shell_output))


def _install_yara():
    logging.info('Installing yara')
    # CAUTION: Yara python binding is installed in bootstrap_common, because it is needed in the frontend as well.
    apt_install_packages('bison', 'flex')
    if check_string_in_command('yara --version', '3.7.1'):
        logging.info('skipping yara installation (already installed)')
    else:
        broken, output = False, ''

        wget_output, wget_code = execute_shell_command_get_return_code('wget https://github.com/VirusTotal/yara/archive/v3.7.1.zip')
        if wget_code != 0:
            raise InstallationError('Error on yara download.\n{}'.format(wget_output))
        zip_output, zip_code = execute_shell_command_get_return_code('unzip v3.7.1.zip')
        if zip_code == 0:
            yara_folder = [child for child in Path('.').iterdir() if 'yara-3.' in child.name][0]
            with OperateInDirectory(yara_folder.name, remove=True):
                os.chmod('bootstrap.sh', 0o775)
                for command in ['./bootstrap.sh', './configure --enable-magic', 'make -j$(nproc)', 'sudo make install']:
                    output, return_code = execute_shell_command_get_return_code(command)
                    if return_code != 0:
                        broken = True
                        break
        else:
            raise InstallationError('Error on yara extraction.\n{}'.format(zip_output))
        Path('v3.7.1.zip').unlink()
        if broken:
            raise InstallationError('Error in yara installation.\n{}'.format(output))
