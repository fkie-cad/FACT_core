#!/usr/bin/env python3

import logging
import pathlib
import urllib.request
from tempfile import TemporaryDirectory

try:
    from helperFunctions.install import OperateInDirectory, check_distribution, run_cmd_with_logging

    from ...installer import AbstractPluginInstaller
except ImportError:
    import sys
    print(
        'Could not import dependencies.\n' +
        'Try starting with "python3 -m plugins.analysis.PLUGIN_NAME.install" from the FACT_core/src directory',
        file=sys.stderr
    )
    sys.exit(1)

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class QemuExecInstaller(AbstractPluginInstaller):
    def install_docker_images(self):
        run_cmd_with_logging(
            'docker build --build-arg=http{,s}_proxy --build-arg=HTTP{,S}_PROXY -t fact/qemu:latest docker',
            shell=True)

    def install_files(self):
        with TemporaryDirectory(dir=str(self.base_path)) as tmp_dir:
            # We download a specific version of the package so no need to
            # update downloaded files
            if (pathlib.Path(f'{self.base_path}/test/data/test_tmp_dir/lib/libc.so.6').exists() and
                    pathlib.Path(f'{self.base_path}/test/data/test_tmp_dir/lib/ld.so.1').exists() and
                    pathlib.Path(f'{self.base_path}/test/data/test_tmp_dir_2/lib/libc.so.6').exists() and
                    pathlib.Path(f'{self.base_path}/test/data/test_tmp_dir_2/lib/ld.so.1').exists()):
                return

            url_libc6_mips = 'http://de.archive.ubuntu.com/ubuntu/pool/universe/c/cross-toolchain-base-ports/libc6-mips-cross_2.23-0ubuntu3cross1_all.deb'
            dest_libc6_mips = f'{tmp_dir}/libc6-mips-cross_2.23-0ubuntu3cross1_all.deb'
            urllib.request.urlretrieve(url_libc6_mips, dest_libc6_mips)
            # We can't use `ar --output` because it was added in 2.34 but
            # debian buster uses 2.31
            with OperateInDirectory(tmp_dir):
                run_cmd_with_logging(f'ar x {dest_libc6_mips} data.tar.xz', shell=True)

            run_cmd_with_logging(f'tar -xf {tmp_dir}/data.tar.xz -C {tmp_dir}', shell=True)
            pathlib.Path('test/data/test_tmp_dir/lib').mkdir(exist_ok=True,
                                                             parents=True)
            pathlib.Path('test/data/test_tmp_dir_2/fact_extracted/lib').mkdir(
                exist_ok=True, parents=True)

            run_cmd_with_logging(
                f'cp {tmp_dir}/usr/mips-linux-gnu/lib/libc-2.23.so test/data/test_tmp_dir/lib/libc.so.6',
                shell=True)
            run_cmd_with_logging(
                f'cp {tmp_dir}/usr/mips-linux-gnu/lib/ld-2.23.so test/data/test_tmp_dir/lib/ld.so.1',
                shell=True)
            run_cmd_with_logging(
                f'mv {tmp_dir}/usr/mips-linux-gnu/lib/libc-2.23.so test/data/test_tmp_dir_2/fact_extracted/lib/libc.so.6',
                shell=True)
            run_cmd_with_logging(
                f'mv {tmp_dir}/usr/mips-linux-gnu/lib/ld-2.23.so test/data/test_tmp_dir_2/fact_extracted/lib/ld.so.1',
                shell=True)


# Alias for generic use
Installer = QemuExecInstaller

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(base_path, distribution)
    installer.install()
