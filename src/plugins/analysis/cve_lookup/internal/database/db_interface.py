import sys
from pathlib import Path

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

    def cpe_matches(self, products: list[str]) -> list[Cpe]:
        '''
        Retrieve a list of Cpe objects that match the given products.
        '''
        return self.session.query(Cpe).filter(Cpe.product.in_(products)).all()

    def associations_lookup(self, cpe_id: str) -> list[Association]:
        '''
        Retrieve a list of Association objects for the given Cpe ID.
        '''
        return self.session.query(Association).filter_by(cpe_id=cpe_id).all()

    def cpe_lookup(self, cpe_id: str) -> Cpe:
        '''
        Retrieve the Cpe object for the given Cpe ID.
        '''
        return self.session.query(Cpe).filter_by(cpe_id=cpe_id).first()

    def cve_lookup(self, cve_id: str) -> Cve:
        '''
        Retrieve the Cve object for the given Cve ID.
        '''
        return self.session.query(Cve).filter_by(cve_id=cve_id).first()
