import sys
from pathlib import Path
from collections import defaultdict

try:
    from ..database.db_connection import DbConnection
    from ..database.schema import Association, Cve, Cpe
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'database'))
    from db_connection import DbConnection
    from schema import Association, Cve, Cpe


class DbInterface:
    DB_PATH = str(Path(__file__).parent / 'cve_cpe.db')

    def __init__(self, connection: DbConnection):
        self.connection = connection
        self.session = self.connection.create_session()

    def match_cpes(self, products: list[str]) -> list[Cpe]:
        """
        Retrieve a dictionary of Cpe objects that match the given products.
        """
        cpe_matches = self.session.query(Cpe).filter(Cpe.product.in_(products)).all()
        return {cpe.cpe_id: cpe for cpe in cpe_matches}

    def get_associations(self, cpe_ids: list[str]) -> dict[str, list[Association]]:
        """
        Retrieve a dictionary of Association objects for the given Cpe IDs.
        """
        association_dict = defaultdict(list)
        associations = self.session.query(Association).filter(Association.cpe_id.in_(cpe_ids)).all()
        for association in associations:
            association_dict[association.cpe_id].append(association)
        return dict(association_dict)

    def get_cves(self, cve_ids: list[str]) -> dict[str, Cve]:
        """
        Retrieve a dictionary of CVE objects for the given CVE IDs.
        """
        cves = self.session.query(Cve).filter(Cve.cve_id.in_(cve_ids)).all()
        return {cve.cve_id: cve for cve in cves}
