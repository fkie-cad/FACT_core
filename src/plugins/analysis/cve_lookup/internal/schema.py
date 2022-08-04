from pathlib import Path

from sqlalchemy import Column, Integer, Text, create_engine
from sqlalchemy.orm import declarative_base

database_path = str(Path(__file__).parent / 'cve_cpe.db')
engine = create_engine(f'sqlite+pysqlite:///{database_path}', future=True)

Base = declarative_base()


class Cpe(Base):
    __tablename__ = 'cpe_table'

    _id = Column(Integer, primary_key=True)
    cpe_id = Column(Text, nullable=False)
    part = Column(Text, nullable=False)
    vendor = Column(Text, nullable=False)
    product = Column(Text, nullable=False)
    version = Column(Text, nullable=False)
    update = Column(Text, nullable=False)
    edition = Column(Text, nullable=False)
    language = Column(Text, nullable=False)
    sw_edition = Column(Text, nullable=False)
    target_sw = Column(Text, nullable=False)
    target_hw = Column(Text, nullable=False)
    other = Column(Text, nullable=False)


class Cve(Base):
    __tablename__ = 'cve_table'

    _id = Column(Integer, primary_key=True)
    cve_id = Column(Text, nullable=False)
    year = Column(Integer, nullable=False)
    cpe_id = Column(Text, nullable=False)
    cvss_v2_score = Column(Text, nullable=False)
    cvss_v3_score = Column(Text, nullable=False)
    part = Column(Text, nullable=False)
    vendor = Column(Text, nullable=False)
    product = Column(Text, nullable=False)
    version = Column(Text, nullable=False)
    update = Column(Text, nullable=False)
    edition = Column(Text, nullable=False)
    language = Column(Text, nullable=False)
    sw_edition = Column(Text, nullable=False)
    target_sw = Column(Text, nullable=False)
    target_hw = Column(Text, nullable=False)
    other = Column(Text, nullable=False)
    version_start_including = Column(Text, nullable=False)
    version_start_excluding = Column(Text, nullable=False)
    version_end_including = Column(Text, nullable=False)
    version_end_excluding = Column(Text, nullable=False)


class Summary(Base):
    __tablename__ = 'summary_table'

    _id = Column(Integer, primary_key=True)
    cve_id = Column(Text, nullable=False)
    year = Column(Integer, nullable=False)
    summary = Column(Text, nullable=False)
    cvss_v2_score = Column(Text, nullable=False)
    cvss_v3_score = Column(Text, nullable=False)

# Note from Jörg: The cve_id and cpe_id shold not update an should be a primary key
