from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Association(Base):
    __tablename__ = 'association'

    cve_id = Column(String(), ForeignKey('cves.cve_id'), primary_key=True)
    cpe_id = Column(String(), ForeignKey('cpes.cpe_id'), primary_key=True)
    version_start_including = Column(String())
    version_start_excluding = Column(String())
    version_end_including = Column(String())
    version_end_excluding = Column(String())

    cpe = relationship('Cpe', back_populates='cves')
    cve = relationship('Cve', back_populates='cpes')

    def __repr__(self) -> str:
        return f'Association({self.cve_id, self.cpe_id})'


class Cve(Base):
    __tablename__ = 'cves'

    cve_id = Column(String(), primary_key=True)
    year = Column(String())
    summary = Column(String())
    cvss_v2_score = Column(String())
    cvss_v3_score = Column(String())
    cpes = relationship(Association, back_populates='cve')

    def __repr__(self) -> str:
        return f'Cve({self.cve_id})'


class Cpe(Base):
    __tablename__ = 'cpes'

    cpe_id = Column(String(), primary_key=True)
    vendor = Column(String())
    product = Column(String())
    version = Column(String())
    update = Column(String())
    cves = relationship(Association, back_populates='cpe')

    def __repr__(self) -> str:
        return f'Cpe({self.cpe_id})'
