import logging
import os
import shutil
from contextlib import suppress
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.config import load_config
from helperFunctions.install import apt_remove_packages, apt_install_packages, apt_upgrade_system, apt_update_sources, \
    apt_autoremove_packages, apt_clean_system, InstallationError, pip_install_packages, pip_remove_packages, \
    install_github_project, pip2_install_packages, pip2_remove_packages, check_string_in_command


def main(distribution):
    if distribution == 'xenial':
        xenial=True
        print('Installing on Ubuntu 16.04')
    elif distribution == 'bionic':
        xenial=False
        print('Installing on Ubuntu 18.04')
    else:
        raise InstallationError('Unsupported distribution {}'.format(distribution))

    '''
    # change cwd to bootstrap dir
    CURRENT_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    cd $CURRENT_FILE_DIR
    '''

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
    apt_install_packages('bison', 'flex', 'libmagic-dev')
    if check_string_in_command('yara --version', '3.7.1'):
        logging.info('skipping yara installation (already installed)')
    else:
        '''
        wget https://github.com/VirusTotal/yara/archive/v3.7.1.zip
        unzip v3.7.1.zip
        cd yara-3.*
        #patch --forward -r - libyara/arena.c ../patches/yara.patchfile
        chmod +x bootstrap.sh
        ./bootstrap.sh
        ./configure --enable-magic
        make -j$(nproc)
        sudo make install
        # CAUTION: Yara python binding is installed in bootstrap_common, because it is needed in the frontend as well.
        cd ..
        sudo rm -fr yara* v3.7.1.zip
        '''
        pass

    ####################################
    #       installing unpacker        #
    ####################################

    apt_install_packages('fakeroot')

    # ---- sasquatch unpacker ----
    # Original: devttys0/sasquatch
    # Ubuntu 18.04 compatiblity issue in original source. Fixed in this fork:
    install_github_project('kartone/sasquatch', ['./build.sh'])

    # ubi_reader
    pip2_install_packages('python-lzo')
    install_github_project('jrspruitt/ubi_reader', ['sudo python2 setup.py install --force'])

    # ---- binwalk ----
    apt_install_packages('libqt4-opengl', 'python3-opengl', 'python3-pyqt4', 'python3-pyqt4.qtopengl', 'mtd-utils', 'gzip', 'bzip2', 'tar', 'arj', 'lhasa', 'p7zip', 'cabextract', 'cramfsprogs', 'cramfsswap', 'squashfs-tools', 'zlib1g-dev', 'liblzma-dev', 'liblzo2-dev', 'liblzo2-dev', 'xvfb')
    apt_install_packages('libcapstone3', 'libcapstone-dev')
    pip_install_packages('pyqtgraph', 'capstone', 'cstruct', 'python-lzo', 'numpy', 'scipy')
    install_github_project('sviehb/jefferson', ['sudo python3 setup.py install'])

    # wget -O - http://my.smithmicro.com/downloads/files/stuffit520.611linux-i386.tar.gz | tar -zxv
    # sudo cp bin/unstuff /usr/local/bin/
    # rm -fr bin doc man

    install_github_project('devttys0/binwalk', ['sudo python3 setup.py install --force'])

    # ---- patool and unpacking backends ----
    pip2_install_packages('patool')
    pip_install_packages('patool')

    apt_install_packages('openjdk-8-jdk')

    apt_install_packages('lrzip', 'cpio', 'unadf', 'rpm2cpio', 'lzop', 'lhasa', 'cabextract', 'zpaq', 'archmage', 'arj', 'xdms', 'rzip', 'lzip', 'unalz', 'unrar', 'unzip', 'gzip', 'nomarch', 'flac', 'unace', 'zoo', 'sharutils')
    apt_install_packages('unar')

    # ---- firmware-mod-kit ----
    install_github_project('rampageX/firmware-mod-kit', ['(cd src && sh configure && make)', 'cp src/yaffs2utils/unyaffs2 src/untrx src/tpl-tool/src/tpl-tool ../../bin/'])

    ####################################
    #  installing common code modules  #
    ####################################

    # common_helper_subprocess
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_process.git')
    # common_helper_yara
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_yara.git')
    # common_helper_unpacking_classifier
    pip_install_packages('git+https://github.com/fkie-cad/common_helper_unpacking_classifier.git')
    # common_analysis_base
    pip_install_packages('git+https://github.com/mass-project/common_analysis_base.git')

    ####################################
    #   install plug-in dependencies   #
    ####################################

    output, return_code = execute_shell_command_get_return_code('find ../plugins -iname "install.sh"')
    if return_code != 0:
        raise InstallationError('Error retrieving plugin installation scripts')
    for install_script in output.splitlines(keepends=False):
        output, return_code = execute_shell_command_get_return_code(install_script)
        if return_code != 0:
            raise InstallationError('Error in installation of {} plugin'.format(Path(install_script).parent.name))

    ####################################
    #    compile custom magic file     #
    ####################################
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

    ####################################
    #       create directories         #
    ####################################

    config = load_config('main.cfg')
    data_dir_name = config.get('data_storage', 'firmware_file_storage_directory')
    Path(data_dir_name).mkdir(parents=True, exist_ok=True)
    os.chmod(data_dir_name, 0o744)
    os.chown(data_dir_name, os.getuid(), os.getgid())

    ####################################
    #    compiling yara signatures     #
    ####################################

    '''
    cd $CURRENT_FILE_DIR
    python3 ../compile_yara_signatures.py
    #compile test signatures
    yarac -d test_flag=false ../test/unit/analysis/test.yara ../analysis/signatures/Yara_Base_Plugin.yc
    
    
    echo "####################################"
    echo "# populating backend installation  #"
    echo "####################################"
    cd ../../
    rm start_fact_backend
    ln -s src/start_fact_backend.py start_fact_backend
    '''

    return 0
