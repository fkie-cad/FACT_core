import sys
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

try:
    from ..internal.schema import Base
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from schema import Base

DB_PATH = str(Path(__file__).parent / 'cve_cpe.db')


class DbConnection:
    def __init__(self):
        self.base = Base
        connection_string = f'sqlite:///{DB_PATH}'
        self.engine = create_engine(connection_string, echo=False)
        self.session_maker = sessionmaker(bind=self.engine)

    def create_tables(self):
        '''
        Creates the database tables based on the defined models.
        '''
        self.base.metadata.create_all(self.engine)
