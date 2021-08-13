#!/usr/bin/env python3

import pathlib
import urllib.request
from tempfile import TemporaryDirectory

from helperFunctions.install import run_cmd_with_logging

from ...installer import AbstractPluginInstaller

# The base directory of the plugin
base_path = pathlib.Path(__file__).resolve().parent


class IpAndUriFinderInstaller(AbstractPluginInstaller):
    def install_files(self):
        with TemporaryDirectory() as tmp_dir:
            # We use a mirror of an old database that should not change
            if pathlib.Path(f'{self.base_path}/bin/GeoLite2-City/').exists():
                return
            pathlib.Path(f'{self.base_path}/bin').mkdir(exist_ok=True)

            url_geolite = 'https://github.com/codeqq/geolite2-city-mirror/raw/master/GeoLite2-City.tar.gz'
            dest_geolite = f'{tmp_dir}/GeoLite2-City.tar.gz'
            urllib.request.urlretrieve(url_geolite, dest_geolite)

            run_cmd_with_logging(f'tar -xf {dest_geolite} --strip-components 1 -C {tmp_dir}', shell=True)
            run_cmd_with_logging(f'mv {tmp_dir} {self.base_path}/bin/GeoLite2-City', shell=True)


# Alias for generic use
Installer = IpAndUriFinderInstaller
