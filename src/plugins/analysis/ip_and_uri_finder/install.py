#!/usr/bin/env python3

import logging
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    from helperFunctions.install import run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class IpAndUriFinderInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_files(self):
        with TemporaryDirectory(dir=str(self.base_path)) as tmp_dir:
            # We use a mirror of an old database that should not change
            if Path(f'{self.base_path}/bin/GeoLite2-City/').exists():
                return
            Path(f'{self.base_path}/bin').mkdir(exist_ok=True)

            url_geolite = 'https://github.com/codeqq/geolite2-city-mirror/raw/master/GeoLite2-City.tar.gz'
            dest_geolite = f'{tmp_dir}/GeoLite2-City.tar.gz'
            urllib.request.urlretrieve(url_geolite, dest_geolite)

            run_cmd_with_logging(f'tar -xf {dest_geolite} -C {tmp_dir}')
            run_cmd_with_logging(f'mv {tmp_dir}/GeoLite2-City_20191029 {self.base_path}/bin/GeoLite2-City')


# Alias for generic use
Installer = IpAndUriFinderInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
