#!/usr/bin/env python3
import os
import logging
from pathlib import Path

try:
    from plugins.installer import AbstractPluginInstaller
    from helperFunctions.install import check_distribution
    from plugins.analysis.cve_lookup.internal.data_parsing import parse_data
    from plugins.analysis.cve_lookup.internal.database.db_setup import DbSetup
    from plugins.analysis.cve_lookup.internal.database.db_connection import DbConnection
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.installer import AbstractPluginInstaller
    from helperFunctions.install import check_distribution
    from plugins.analysis.cve_lookup.internal.data_parsing import parse_data
    from plugins.analysis.cve_lookup.internal.database.db_setup import DbSetup
    from plugins.analysis.cve_lookup.internal.database.db_connection import DbConnection


class CveLookupInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_files(self):
        """
        Install files for the CVE lookup plugin.
        """
        os.chdir('internal')
        cve_list = parse_data()
        connection = DbConnection()
        connection.drop_tables()
        db = DbSetup(connection)
        db.add_cve_items(cve_list)
        os.chdir(self.base_path)


# Alias for generic use
Installer = CveLookupInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    distribution = check_distribution()
    installer = Installer(distribution)
    installer.install()
