from __future__ import annotations

import logging

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Date,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    Table,
    event,
    select,
)
from sqlalchemy.dialects.postgresql import ARRAY, CHAR, JSONB, VARCHAR
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import Session, backref, declarative_base, relationship

Base = declarative_base()
UID = VARCHAR(78)

# primary_key=True implies `unique=True` and `nullable=False`


class AnalysisEntry(Base):
    __tablename__ = 'analysis'

    uid = Column(UID, ForeignKey('file_object.uid'))
    plugin = Column(VARCHAR(64), nullable=False)
    plugin_version = Column(VARCHAR(16), nullable=False)
    system_version = Column(VARCHAR)
    analysis_date = Column(Float, nullable=False)
    summary = Column(ARRAY(VARCHAR, dimensions=1), default=[])
    tags = Column(MutableDict.as_mutable(JSONB))
    result = Column(MutableDict.as_mutable(JSONB), default={})

    file_object = relationship('FileObjectEntry', back_populates='analyses')

    __table_args__ = (PrimaryKeyConstraint('uid', 'plugin', name='_analysis_primary_key'),)

    def __repr__(self) -> str:
        return f'AnalysisEntry({self.uid}, {self.plugin}, {self.plugin_version})'


included_files_table = Table(
    'included_files',
    Base.metadata,
    Column('parent_uid', UID, ForeignKey('file_object.uid'), primary_key=True),
    Column('child_uid', UID, ForeignKey('file_object.uid'), primary_key=True),
)

fw_files_table = Table(
    'fw_files',
    Base.metadata,
    Column('root_uid', UID, ForeignKey('file_object.uid'), primary_key=True),
    Column('file_uid', UID, ForeignKey('file_object.uid'), primary_key=True),
)


comparisons_table = Table(
    'compared_files',
    Base.metadata,
    Column('comparison_id', VARCHAR, ForeignKey('comparison.comparison_id'), primary_key=True),
    Column('file_uid', UID, ForeignKey('file_object.uid'), primary_key=True),
)


class FileObjectEntry(Base):
    __tablename__ = 'file_object'

    uid = Column(UID, primary_key=True)
    sha256 = Column(CHAR(64), nullable=False)
    file_name = Column(VARCHAR, nullable=False)
    depth = Column(Integer, nullable=False)
    size = Column(BigInteger, nullable=False)
    comments = Column(MutableList.as_mutable(JSONB))
    virtual_file_paths = Column(MutableDict.as_mutable(JSONB))
    is_firmware = Column(Boolean, nullable=False)

    firmware = relationship('FirmwareEntry', back_populates='root_object', uselist=False, cascade='all, delete')  # 1:1
    parent_files = relationship(  # n:n
        'FileObjectEntry',
        secondary=included_files_table,
        primaryjoin=uid == included_files_table.c.child_uid,
        secondaryjoin=uid == included_files_table.c.parent_uid,
        back_populates='included_files',
    )
    included_files = relationship(  # n:n
        'FileObjectEntry',
        secondary=included_files_table,
        primaryjoin=uid == included_files_table.c.parent_uid,
        secondaryjoin=uid == included_files_table.c.child_uid,
        back_populates='parent_files',
    )
    root_firmware = relationship(  # n:n
        'FileObjectEntry',
        secondary=fw_files_table,
        primaryjoin=uid == fw_files_table.c.file_uid,
        secondaryjoin=uid == fw_files_table.c.root_uid,
        backref=backref('all_included_files'),
    )
    analyses = relationship(  # 1:n
        'AnalysisEntry',
        back_populates='file_object',
        cascade='all, delete-orphan',  # the analysis should be deleted when the file object is deleted
    )
    comparisons = relationship(  # n:n
        'ComparisonEntry',
        secondary=comparisons_table,
        cascade='all, delete',  # comparisons should also be deleted when the file object is deleted
        backref=backref('file_objects'),
    )

    def get_included_uids(self) -> set[str]:
        return {child.uid for child in self.included_files}

    def get_parent_uids(self) -> set[str]:
        return {parent.uid for parent in self.parent_files}

    def __repr__(self) -> str:
        return f'FileObject({self.uid}, {self.file_name}, {self.is_firmware})'


class FirmwareEntry(Base):
    __tablename__ = 'firmware'

    uid = Column(UID, ForeignKey('file_object.uid'), primary_key=True)
    submission_date = Column(Float, nullable=False)
    release_date = Column(Date, nullable=False)
    version = Column(VARCHAR, nullable=False)
    vendor = Column(VARCHAR, nullable=False)
    device_name = Column(VARCHAR, nullable=False)
    device_class = Column(VARCHAR, nullable=False)
    device_part = Column(VARCHAR, nullable=False)
    firmware_tags = Column(ARRAY(VARCHAR, dimensions=1))  # list of strings

    root_object = relationship('FileObjectEntry', back_populates='firmware')


class ComparisonEntry(Base):
    __tablename__ = 'comparison'

    comparison_id = Column(VARCHAR, primary_key=True)
    submission_date = Column(Float, nullable=False)
    data = Column(MutableDict.as_mutable(JSONB))


class StatsEntry(Base):
    __tablename__ = 'stats'

    name = Column(VARCHAR, primary_key=True)
    data = Column(MutableDict.as_mutable(JSONB), nullable=False)


class SearchCacheEntry(Base):
    __tablename__ = 'search_cache'

    uid = Column(UID, primary_key=True)
    query = Column(VARCHAR, nullable=False)  # the query that searches for the files that the YARA rule matched
    yara_rule = Column(VARCHAR, nullable=False)


class WebInterfaceTemplateEntry(Base):
    __tablename__ = 'templates'

    plugin = Column(VARCHAR, primary_key=True)
    template = Column(LargeBinary, nullable=False)


@event.listens_for(Session, 'persistent_to_deleted')
def delete_file_orphans(session, deleted_object):
    """
    Delete file_object DB entry if there are no parents left (i.e. when the last
    parent is deleted). Regular postgres cascade delete operation would delete the
    entry if any parent was removed, and we don't want that, obviously. Instead,
    we need this event, that is triggered each time an object from the DB is deleted.
    """
    if isinstance(deleted_object, FileObjectEntry):
        query = select(FileObjectEntry).filter(~FileObjectEntry.parent_files.any(), ~FileObjectEntry.is_firmware)
        for item in session.execute(query).scalars():
            logging.debug(f'deletion of {deleted_object} triggers deletion of {item} (cascade)')
            session.delete(item)
