import os
import pathlib

from helperFunctions.install import run_cmd_with_logging


class AbstractPluginInstaller:
    # Even if some functoins don't need self we want to have them nicely
    # grouped in this class
    # pylint:disable=no-self-use
    def __init__(self, base_path: pathlib.Path, distribution, skip_docker=False):
        self.base_path = base_path
        self.distribution = distribution
        self.build_path = base_path / 'build'
        self.skip_docker = skip_docker

    def install(self):
        cwd = os.getcwd()
        os.chdir(self.base_path)
        self.install_system_packages()
        self.install_pip_packages()
        self.install_other_packages()

        self.install_files()

        self.build_path.mkdir(exist_ok=True)
        os.chdir(self.build_path)
        self.build()
        run_cmd_with_logging(f'sudo rm -rf {self.build_path}')
        os.chdir(self.base_path)

        if not self.skip_docker:
            self.install_docker_images()

        self.do_last()

        os.chdir(cwd)

    def install_docker_images(self):
        '''
        Build/Pull docker images
        '''

    def install_system_packages(self):
        '''
        Install packages with apt/dnf
        '''
        build_pkg_path = './apt-pkgs-build.txt' if self.distribution != 'fedora' else './dnf-pkgs-build.txt'
        runtime_pkg_path = './apt-pkgs-runtime.txt' if self.distribution != 'fedora' else './dnf-pkgs-runtime.txt'

        build_list = []
        # TODO use read_package_list_from_file when #618 is merged
        if os.access(build_pkg_path, os.R_OK):
            with open(build_pkg_path) as build_f:
                build_list = build_f.read().splitlines()

        runtime_list = []
        # TODO use read_package_list_from_file when #618 is merged
        if os.access(runtime_pkg_path, os.R_OK):
            with open(runtime_pkg_path) as runtime_f:
                runtime_list = runtime_f.read().splitlines()

        pgk_mgr_cmd = 'apt install -y' if self.distribution != 'fedora' else 'dnf install -y'
        pkgs_to_install = ' '.join(build_list + runtime_list)

        if len(pkgs_to_install) == 0:
            return

        run_cmd_with_logging(f'sudo {pgk_mgr_cmd} {pkgs_to_install}')

    def install_pip_packages(self):
        '''
        Install packages with pip
        '''
        if pathlib.Path('./requirements.txt').exists():
            run_cmd_with_logging('sudo pip3 install -r ./requirements.txt')

    def install_other_packages(self):
        '''
        Install packages with package managers other than pip/dnf/apt.
        '''

    def do_last(self):
        pass

    def install_files(self):
        '''
        Download and install files.
        '''

    def build(self):
        '''
        Build and install projects that can't be installed through a package
        manager
        '''
        # This function is kind of ugly
        # It esentially does what a Makefile should do but worse
        # In the future we hope to not need to build things ourself
