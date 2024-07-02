from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..helper_functions import CveEntry, replace_wildcards
from .schema import Association, Cpe, Cve

if TYPE_CHECKING:
    from .db_connection import DbConnection

CPE_SPLIT_REGEX = re.compile(r'(?<![\\:]):(?!:)|(?<=\\:):')  # don't split on '::' or '\:' but split on '\::'


class DbSetup:
    DB_PATH = str(Path(__file__).parent / 'cve_cpe.db')

    def __init__(self, connection: DbConnection):
        self.connection = connection
        self.connection.create_tables()
        self.session = self.connection.create_session()

    def create_cve(self, cve_item: CveEntry) -> Cve:
        """
        Create a Cve object from a CveEntry object.
        """
        year = cve_item.cve_id.split('-')[1]
        return Cve(
            cve_id=cve_item.cve_id,
            year=year,
            summary=cve_item.summary,
            cvss_score=cve_item.impact,
        )

    def create_cpe(self, cpe_id: str):
        """
        Create a Cpe object from a CPE ID.
        """
        cpe_elements = replace_wildcards(CPE_SPLIT_REGEX.split(cpe_id)[3:])
        vendor = cpe_elements[0]
        product = cpe_elements[1]
        version = cpe_elements[2]
        update = cpe_elements[3]

        return Cpe(
            cpe_id=cpe_id,
            vendor=vendor,
            product=product,
            version=version,
            update=update,
        )

    def add_cve_items(self, cve_list: list[CveEntry]):
        """
        Add CVE items to the database.
        """
        existing_cve_ids = set()
        existing_cpe_ids = set()

        cves = []
        associations = []
        cpes = []

        for cve_item in cve_list:
            if cve_item.cve_id not in existing_cve_ids:
                cves.append(self.create_cve(cve_item))
                for cpe_entry in cve_item.cpe_entries:
                    (
                        cpe_id,
                        version_start_including,
                        version_start_excluding,
                        version_end_including,
                        version_end_excluding,
                    ) = cpe_entry
                    if cpe_id not in existing_cpe_ids:
                        cpes.append(self.create_cpe(cpe_id))
                        existing_cpe_ids.add(cpe_id)
                    associations.append(
                        Association(
                            cve_id=cve_item.cve_id,
                            cpe_id=cpe_id,
                            version_start_including=version_start_including,
                            version_start_excluding=version_start_excluding,
                            version_end_including=version_end_including,
                            version_end_excluding=version_end_excluding,
                        )
                    )
                existing_cve_ids.add(cve_item.cve_id)
        self.session.bulk_save_objects(cves + associations + cpes)
        self.session.commit()
