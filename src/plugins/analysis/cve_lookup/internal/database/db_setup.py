import re
import sys
from pathlib import Path

try:
    from ..database.db_connection import DbConnection
    from ..database.schema import Association, Cve, Cpe
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'database'))
    from db_connection import DbConnection
    from schema import Association, Cve, Cpe

try:
    from ..internal.helper_functions import CveEntry, replace_wildcards
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent.parent / 'internal'))
    from helper_functions import CveEntry, replace_wildcards

CPE_SPLIT_REGEX = re.compile(r'(?<![\\:]):(?!:)|(?<=\\:):')  # don't split on '::' or '\:' but split on '\::'


class DbSetup:
    DB_PATH = str(Path(__file__).parent / 'cve_cpe.db')

    def __init__(self, connection: DbConnection):
        self.connection = connection
        self.connection.create_tables()
        self.session = self.connection.create_session()

    def create_cve(self, cve_item: CveEntry) -> Cve:
        '''
        Create a Cve object from a CveEntry object.
        '''
        year = cve_item.cve_id.split('-')[1]
        score_v2 = cve_item.impact.get('cvssMetricV2', 'N/A')
        score_v30 = cve_item.impact.get('cvssMetricV30', 'N/A')
        score_v3 = cve_item.impact.get('cvssMetricV31', score_v30)
        return Cve(
            cve_id=cve_item.cve_id,
            year=year,
            summary=cve_item.summary,
            cvss_v2_score=score_v2,
            cvss_v3_score=score_v3,
        )

    def create_cpe(self, cpe_id: str) -> Cpe:
        '''
        Create a Cpe object from a CPE ID.
        '''
        cpe_elements = replace_wildcards(CPE_SPLIT_REGEX.split(cpe_id)[2:])
        (
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
            sw_edition,
            target_sw,
            target_hw,
            other,
        ) = cpe_elements
        return Cpe(
            cpe_id=cpe_id,
            part=part,
            vendor=vendor,
            product=product,
            version=version,
            update=update,
            edition=edition,
            language=language,
            sw_edition=sw_edition,
            target_sw=target_sw,
            target_hw=target_hw,
            other=other,
        )

    def add_cve_items(self, cve_list: list[CveEntry]):
        '''
        Add CVE items to the database.
        '''
        existing_cve_ids = {cve.cve_id for cve in self.session.query(Cve.cve_id).all()}
        existing_cpe_ids = {cpe.cpe_id for cpe in self.session.query(Cpe.cpe_id).all()}

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
