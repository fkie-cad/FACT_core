from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from ..helper_functions import CveEntry, replace_wildcards
from .schema import Association, Base, Cpe, Cve

if TYPE_CHECKING:
    from .db_connection import DbConnection

CPE_SPLIT_REGEX = re.compile(r'(?<![\\:]):(?!:)|(?<=\\:):')  # don't split on '::' or '\:' but split on '\::'


class DbSetup:
    DB_PATH = str(Path(__file__).parent / 'cve_cpe.db')

    def __init__(self, connection: DbConnection):
        self.connection = connection
        self.connection.create_tables()
        self.session = self.connection.create_session()
        self.existing_cve_ids = set()
        self.existing_cpe_ids = set()

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

    def create_association(self, cve_id: str, cpe_entry: tuple[str, str, str, str, str]) -> Association:
        """
        Create an Association object from a CVE ID and a CPE entry.
        """
        (
            cpe_id,
            version_start_including,
            version_start_excluding,
            version_end_including,
            version_end_excluding,
        ) = cpe_entry
        return Association(
            cve_id=cve_id,
            cpe_id=cpe_id,
            version_start_including=version_start_including,
            version_start_excluding=version_start_excluding,
            version_end_including=version_end_including,
            version_end_excluding=version_end_excluding,
        )

    def add_cve_items(self, cve_list: Iterable[CveEntry], chunk_size: int = 2**12):
        """
        Add CVE items to the database chunk-wise.
        """

        db_objects: list[Base] = []

        for cve_item in cve_list:
            if cve_item.cve_id not in self.existing_cve_ids:
                db_objects.extend(self._create_db_objects_for_cve(cve_item))
                if len(db_objects) >= chunk_size:
                    self._save_objects(db_objects)
                    db_objects.clear()
        if db_objects:
            self._save_objects(db_objects)

    def _create_db_objects_for_cve(self, cve_item: CveEntry) -> Iterable[Base]:
        yield self.create_cve(cve_item)
        for cpe_entry in cve_item.cpe_entries:
            if (cpe_id := cpe_entry[0]) not in self.existing_cpe_ids:
                yield self.create_cpe(cpe_id)
                self.existing_cpe_ids.add(cpe_id)
            yield self.create_association(cve_item.cve_id, cpe_entry)
        self.existing_cve_ids.add(cve_item.cve_id)

    def _save_objects(self, objects: list[Base]):
        self.session.bulk_save_objects(objects)
        self.session.commit()
