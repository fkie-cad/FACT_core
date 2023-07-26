#!/usr/bin/env python3

import logging
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    from helperFunctions.install import OperateInDirectory, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import OperateInDirectory, run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class QemuExecInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        self._build_docker_image('fact/qemu-exec:alpine-3.18')

    def install_files(self):
        with TemporaryDirectory(dir=str(self.base_path)) as tmp_dir:
            # We download a specific version of the package so no need to
            # update downloaded files
            if (
                Path(f'{self.base_path}/test/data/test_tmp_dir/lib/libc.so.6').exists()
                and Path(f'{self.base_path}/test/data/test_tmp_dir/lib/ld.so.1').exists()
                and Path(f'{self.base_path}/test/data/test_tmp_dir_2/lib/libc.so.6').exists()
                and Path(f'{self.base_path}/test/data/test_tmp_dir_2/lib/ld.so.1').exists()
            ):
                return

            url_libc6_mips = 'http://de.archive.ubuntu.com/ubuntu/pool/universe/c/cross-toolchain-base-ports/libc6-mips-cross_2.23-0ubuntu3cross1_all.deb'
            dest_libc6_mips = f'{tmp_dir}/libc6-mips-cross_2.23-0ubuntu3cross1_all.deb'
            urllib.request.urlretrieve(url_libc6_mips, dest_libc6_mips)
            # We can't use `ar --output` because it was added in 2.34 but
            # debian buster uses 2.31
            with OperateInDirectory(tmp_dir):
                run_cmd_with_logging(f'ar x {dest_libc6_mips} data.tar.xz')

            run_cmd_with_logging(f'tar -xf {tmp_dir}/data.tar.xz -C {tmp_dir}')
            Path('test/data/test_tmp_dir/lib').mkdir(exist_ok=True, parents=True)
            Path('test/data/test_tmp_dir_2/fact_extracted/lib').mkdir(exist_ok=True, parents=True)

            run_cmd_with_logging(
                f'cp {tmp_dir}/usr/mips-linux-gnu/lib/libc-2.23.so test/data/test_tmp_dir/lib/libc.so.6'
            )
            run_cmd_with_logging(f'cp {tmp_dir}/usr/mips-linux-gnu/lib/ld-2.23.so test/data/test_tmp_dir/lib/ld.so.1')
            run_cmd_with_logging(
                f'mv {tmp_dir}/usr/mips-linux-gnu/lib/libc-2.23.so test/data/test_tmp_dir_2/fact_extracted/lib/libc.so.6'  # noqa: E501
            )
            run_cmd_with_logging(
                f'mv {tmp_dir}/usr/mips-linux-gnu/lib/ld-2.23.so test/data/test_tmp_dir_2/fact_extracted/lib/ld.so.1'
            )


# Alias for generic use
Installer = QemuExecInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
