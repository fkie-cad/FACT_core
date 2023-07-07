import sys
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

try:
    from ..database.schema import Base
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'database'))
    from schema import Base


class DbConnection:
    DB_PATH = str(Path(__file__).parent / 'cve_cpe.db')

    def __init__(self, connection_string: str = f'sqlite:///{DB_PATH}'):
        self.connection_string = connection_string
        self.base = Base
        self.engine = create_engine(self.connection_string, echo=False)
        self.session_maker = sessionmaker(bind=self.engine)

    def create_session(self):
        '''
        Creates a new session using the session maker.
        '''
        return self.session_maker()

    def create_tables(self):
        '''
        Creates the database tables based on the defined models.
        '''
        self.base.metadata.create_all(self.engine)

    def drop_tables(self):
        '''
        Drop the database tables based on the defined models.
        '''
        self.base.metadata.drop_all(self.engine)
