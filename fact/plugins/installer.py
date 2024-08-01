from __future__ import annotations

import os
from pathlib import Path

from helperFunctions.install import (
    check_distribution,
    install_pip_packages,
    read_package_list_from_file,
    run_cmd_with_logging,
)


class AbstractPluginInstaller:
    """A class that is used to handle plugin installation.
    Any class subclassing it may overwrite any public method except :py:func:`install`.
    You may assume that the cwd is ``self.base_path``.
    If any other method than :py:func:`install` is called, then the caller has to ensure this.

    :param distribution: The distribution on which the installer is executed. See :py:func:`~helperFunctions.install.check_distribution`
    :param skip_docker: Whether or not to do anything docker related.
    """  # noqa: E501

    # Even if some functions don't need self we want to have them nicely
    # grouped in this class

    _skip_docker_env = os.getenv('FACT_INSTALLER_SKIP_DOCKER') is not None
    #: The base directory of the plugin
    #: Must be overwritten by a class variable of a child class
    base_path = None

    def __init__(self, distribution: str | None = None, skip_docker: bool = _skip_docker_env):
        self.distribution = distribution or check_distribution()
        self.build_path = self.base_path / 'build'
        self.skip_docker = skip_docker

    def install(self):
        """Completely install the plugin."""
        cwd = os.getcwd()  # noqa: PTH109
        os.chdir(self.base_path)
        self.install_system_packages()
        self.install_pip_packages()
        self.install_other_packages()

        self.install_files()

        try:
            self.build_path.mkdir(exist_ok=True)
            os.chdir(self.build_path)
            self.build()
        finally:
            run_cmd_with_logging(f'sudo rm -rf {self.build_path}')
            os.chdir(self.base_path)

        if not self.skip_docker:
            self.install_docker_images()

        os.chdir(cwd)

    def install_docker_images(self):
        """
        Build/Pull docker images
        """

    def install_system_packages(self):
        """
        Install packages with apt/dnf
        """
        build_pkg_path = Path('./apt-pkgs-build.txt' if self.distribution != 'fedora' else './dnf-pkgs-build.txt')
        runtime_pkg_path = Path('./apt-pkgs-runtime.txt' if self.distribution != 'fedora' else './dnf-pkgs-runtime.txt')

        pkg_list = _read_packages(build_pkg_path) + _read_packages(runtime_pkg_path)

        pgk_mgr_cmd = 'apt install -y' if self.distribution != 'fedora' else 'dnf install -y'
        pkgs_to_install = ' '.join(pkg_list)

        if len(pkgs_to_install) == 0:
            return

        run_cmd_with_logging(f'sudo {pgk_mgr_cmd} {pkgs_to_install}')

    def install_pip_packages(self):
        """
        Install packages with pip
        """
        requirements_path = self.base_path / 'requirements.txt'
        if requirements_path.exists():
            install_pip_packages(requirements_path)

    def install_other_packages(self):
        """
        Install packages with package managers other than pip/dnf/apt.
        """

    def install_files(self):
        """
        Download and install files.
        """

    def build(self):
        """
        Build and install projects that can't be installed through a package
        manager
        """

    def _build_docker_image(self, tag: str, dockerfile_path: Path | None = None):
        if not dockerfile_path:
            dockerfile_path = self.base_path / 'docker'
        run_cmd_with_logging(f'docker build -t {tag} {dockerfile_path}')


def _read_packages(package_file: Path):
    return read_package_list_from_file(package_file) if package_file.exists() else []
