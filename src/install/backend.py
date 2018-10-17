import logging
import os
import shutil
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code

from compile_yara_signatures import main as compile_signatures
from helperFunctions.config import load_config
from helperFunctions.install import apt_remove_packages, apt_install_packages, InstallationError, pip_install_packages, \
    install_github_project, pip2_install_packages, pip2_remove_packages, check_string_in_command, OperateInDirectory


def main(distribution):
    # dependencies
    apt_install_packages('python-dev', 'python-setuptools')
    apt_install_packages('libjpeg-dev', 'liblzma-dev', 'liblzo2-dev', 'zlib1g-dev')
    apt_install_packages('libssl-dev python3-tk')
    pip_install_packages('pluginbase', 'Pillow', 'cryptography', 'pyopenssl', 'entropy', 'matplotlib')

    apt_install_packages('python-pip')
    # removes due to compatibilty reasons
    apt_remove_packages('python-lzma')
    pip2_remove_packages('pyliblzma')
    apt_install_packages('python-lzma')

    # install yara
    _install_yara()

    # installing unpacker
    _install_unpacker(distribution == 'xenial')

    # installing common code modules
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_process.git')
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_yara.git')
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_unpacking_classifier.git')
    pip_install_packages('git+https://github.com/mass-project/common_analysis_base.git')

    # install plug-in dependencies
    _install_plugins()

    # compile custom magic file
    '''
    cd $CURRENT_FILE_DIR

    cat ../mime/custom_* > ../mime/custommime
    (cd ../mime && file -C -m custommime && mv -f custommime.mgc ../bin/)
    rm ../mime/custommime

    echo "######################################"
    echo "#       configure environment        #"
    echo "######################################"
    echo "add rules to sudo..."
    # Insert additional changes to the sudoers file by applying the syntax used below
    CURUSER=$(whoami 2>&1)
    printf "$CURUSER\tALL=NOPASSWD: /bin/mount \n\
    $CURUSER\tALL=NOPASSWD: /bin/umount \n\
    $CURUSER\tALL=NOPASSWD: /usr/local/bin/sasquatch \n\
    $CURUSER\tALL=NOPASSWD: /bin/rm \n\
    $CURUSER\tALL=NOPASSWD: /bin/cp \n\
    $CURUSER\tALL=NOPASSWD: /bin/mknod \n\
    $CURUSER\tALL=NOPASSWD: /bin/dd \n\
    $CURUSER\tALL=NOPASSWD: /bin/chown\n" > /tmp/faf_overrides
    sudo chown root:root /tmp/faf_overrides
    sudo mv /tmp/faf_overrides /etc/sudoers.d/faf_overrides

    echo "set environment variables..."
    sudo cp -f fact_env.sh /etc/profile.d/
    sudo chmod 755 /etc/profile.d/fact_env.sh
    source /etc/profile
    '''

    # create directories
    _create_firmware_directory()

    # compiling yara signatures
    compile_signatures()
    yarac_output, yarac_return = execute_shell_command_get_return_code('yarac -d test_flag=false ../test/unit/analysis/test.yara ../analysis/signatures/Yara_Base_Plugin.yc')
    if yarac_return != 0:
        raise InstallationError('Failed to compile yara test signatures')

    # cd ../../
    # rm start_fact_backend
    # ln -s src/start_fact_backend.py start_fact_backend

    return 0


def _install_unpacker(xenial):
    apt_install_packages('fakeroot')
    # ---- sasquatch unpacker ----
    # Original: devttys0/sasquatch
    # Ubuntu 18.04 compatiblity issue in original source. Fixed in this fork:
    install_github_project('kartone/sasquatch', ['./build.sh'])
    # ubi_reader
    pip2_install_packages('python-lzo')
    install_github_project('jrspruitt/ubi_reader', ['sudo python2 setup.py install --force'])
    # binwalk
    if xenial:
        # Replace by
        # wget -O - https://sourceforge.net/projects/cramfs/files/cramfs/1.1/cramfs-1.1.tar.gz/download | tar -zxv
        # cd cramfs-1.1
        # sudo install cramfsck mkcramfs /usr/local/bin
        # cd ..
        # rm -rf cramfs-1.1
        apt_install_packages('cramfsprogs')
    apt_install_packages('libqt4-opengl', 'python3-opengl', 'python3-pyqt4', 'python3-pyqt4.qtopengl', 'mtd-utils',
                         'gzip', 'bzip2', 'tar', 'arj', 'lhasa', 'cabextract', 'cramfsswap', 'squashfs-tools',
                         'zlib1g-dev', 'liblzma-dev', 'liblzo2-dev', 'liblzo2-dev', 'xvfb')
    apt_install_packages('libcapstone3', 'libcapstone-dev')
    pip_install_packages('pyqtgraph', 'capstone', 'cstruct', 'python-lzo', 'numpy', 'scipy')
    install_github_project('sviehb/jefferson', ['sudo python3 setup.py install'])
    _install_stuffit()
    install_github_project('devttys0/binwalk', ['sudo python3 setup.py install --force'])
    # patool and unpacking backends
    pip2_install_packages('patool')
    pip_install_packages('patool')
    apt_install_packages('openjdk-8-jdk')
    if xenial:
        apt_install_packages('zoo')
    apt_install_packages('lrzip', 'cpio', 'unadf', 'rpm2cpio', 'lzop', 'lhasa', 'cabextract', 'zpaq', 'archmage', 'arj',
                         'xdms', 'rzip', 'lzip', 'unalz', 'unrar', 'unzip', 'gzip', 'nomarch', 'flac', 'unace',
                         'sharutils')
    apt_install_packages('unar')
    # firmware-mod-kit
    install_github_project('rampageX/firmware-mod-kit', ['(cd src && sh configure && make)',
                                                         'cp src/yaffs2utils/unyaffs2 src/untrx src/tpl-tool/src/tpl-tool ../../bin/'])


def _create_firmware_directory():
    logging.info('Creating firmware directory')

    config = load_config('main.cfg')
    data_dir_name = config.get('data_storage', 'firmware_file_storage_directory')
    Path(data_dir_name).mkdir(parents=True, exist_ok=True)
    os.chmod(data_dir_name, 0o744)
    os.chown(data_dir_name, os.getuid(), os.getgid())


def _install_plugins():
    logging.info('Installing plugins')
    output, return_code = execute_shell_command_get_return_code('find ../plugins -iname "install.sh"')
    if return_code != 0:
        raise InstallationError('Error retrieving plugin installation scripts')
    for install_script in output.splitlines(keepends=False):
        logging.info('Running {}'.format(install_script))
        output, return_code = execute_shell_command_get_return_code(install_script)
        if return_code != 0:
            raise InstallationError('Error in installation of {} plugin'.format(Path(install_script).parent.name))


def _install_yara():
    logging.info('Installing yara')
    # CAUTION: Yara python binding is installed in bootstrap_common, because it is needed in the frontend as well.
    apt_install_packages('bison', 'flex', 'libmagic-dev')
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


def _install_stuffit():
    logging.info('Installing stuffit')
    wget_output, wget_code = execute_shell_command_get_return_code('wget -O - http://my.smithmicro.com/downloads/files/stuffit520.611linux-i386.tar.gz | tar -zxv')
    if wget_code == 0:
        cp_output, cp_code = execute_shell_command_get_return_code('sudo cp bin/unstuff /usr/local/bin/')
    else:
        cp_code = 255
    rm_output, rm_code = execute_shell_command_get_return_code('rm -fr bin doc man')
    if not all(code == 0 for code in (wget_code, cp_code, rm_code)):
        raise InstallationError('Error in installation of unstuff')
