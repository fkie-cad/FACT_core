#!/usr/bin/env python3
import logging
import os
from pathlib import Path

try:
    from plugins.analysis.cve_lookup.internal.data_parsing import parse_data
    from plugins.analysis.cve_lookup.internal.database.db_connection import DbConnection
    from plugins.analysis.cve_lookup.internal.database.db_setup import DbSetup
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from plugins.analysis.cve_lookup.internal.data_parsing import parse_data
    from plugins.analysis.cve_lookup.internal.database.db_connection import DbConnection
    from plugins.analysis.cve_lookup.internal.database.db_setup import DbSetup
    from plugins.installer import AbstractPluginInstaller


class CveLookupInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_files(self):
        """
        Install files for the CVE lookup plugin.
        """
        os.chdir('internal')
        connection = DbConnection()
        connection.drop_tables()
        db = DbSetup(connection)
        db.add_cve_items(parse_data())
        os.chdir(self.base_path)


# Alias for generic use
Installer = CveLookupInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
