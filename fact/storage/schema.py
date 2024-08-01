from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Date,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    Table,
    delete,
    event,
)
from sqlalchemy.dialects.postgresql import ARRAY, CHAR, JSONB, VARCHAR
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import Session, backref, declarative_base, mapped_column, relationship

Base = declarative_base()
UID = VARCHAR(78)

# primary_key=True implies `unique=True` and `nullable=False`


class AnalysisEntry(Base):
    __tablename__ = 'analysis'

    uid = mapped_column(UID, ForeignKey('file_object.uid', ondelete='CASCADE'), index=True)
    plugin = mapped_column(VARCHAR(64), nullable=False)
    plugin_version = mapped_column(VARCHAR(16), nullable=False)
    system_version = mapped_column(VARCHAR)
    analysis_date = mapped_column(Float, nullable=False)
    summary = mapped_column(ARRAY(VARCHAR, dimensions=1), nullable=True)
    tags = mapped_column(MutableDict.as_mutable(JSONB), nullable=True)
    result = mapped_column(MutableDict.as_mutable(JSONB), nullable=True)

    file_object = relationship('FileObjectEntry', back_populates='analyses')

    __table_args__ = (
        PrimaryKeyConstraint('uid', 'plugin', name='_analysis_primary_key'),
        Index('result_gin_index', 'result', postgresql_using='gin'),
    )

    def __repr__(self) -> str:
        return f'AnalysisEntry({self.uid}, {self.plugin}, {self.plugin_version})'


included_files_table = Table(
    'included_files',
    Base.metadata,
    Column('parent_uid', UID, ForeignKey('file_object.uid', ondelete='CASCADE'), primary_key=True, index=True),
    Column('child_uid', UID, ForeignKey('file_object.uid', ondelete='CASCADE'), primary_key=True, index=True),
)

fw_files_table = Table(
    'fw_files',
    Base.metadata,
    Column('root_uid', UID, ForeignKey('file_object.uid', ondelete='CASCADE'), primary_key=True, index=True),
    Column('file_uid', UID, ForeignKey('file_object.uid', ondelete='CASCADE'), primary_key=True, index=True),
)


comparisons_table = Table(
    'compared_files',
    Base.metadata,
    Column('comparison_id', VARCHAR, ForeignKey('comparison.comparison_id', ondelete='CASCADE'), primary_key=True),
    Column('file_uid', UID, ForeignKey('file_object.uid', ondelete='CASCADE'), primary_key=True),
)


class FileObjectEntry(Base):
    __tablename__ = 'file_object'

    uid = mapped_column(UID, primary_key=True)
    sha256 = mapped_column(CHAR(64), nullable=False)
    file_name = mapped_column(VARCHAR, nullable=False)
    depth = mapped_column(Integer, nullable=False)
    size = mapped_column(BigInteger, nullable=False)
    comments = mapped_column(MutableList.as_mutable(JSONB))
    is_firmware = mapped_column(Boolean, nullable=False)

    firmware = relationship(  # 1:1
        'FirmwareEntry',
        back_populates='root_object',
        uselist=False,
        cascade='all, delete',
    )
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

    def get_parent_fw_uids(self) -> set[str]:
        return {fw.uid for fw in self.root_firmware}

    def __repr__(self) -> str:
        return f'FileObject({self.uid}, {self.file_name}, {self.is_firmware})'


class FirmwareEntry(Base):
    __tablename__ = 'firmware'

    uid = mapped_column(UID, ForeignKey('file_object.uid', ondelete='CASCADE'), primary_key=True)
    submission_date = mapped_column(Float, nullable=False)
    release_date = mapped_column(Date, nullable=False)
    version = mapped_column(VARCHAR, nullable=False)
    vendor = mapped_column(VARCHAR, nullable=False)
    device_name = mapped_column(VARCHAR, nullable=False)
    device_class = mapped_column(VARCHAR, nullable=False)
    device_part = mapped_column(VARCHAR, nullable=False)
    firmware_tags = mapped_column(ARRAY(VARCHAR, dimensions=1))  # list of strings

    root_object = relationship('FileObjectEntry', back_populates='firmware')


class ComparisonEntry(Base):
    __tablename__ = 'comparison'

    comparison_id = mapped_column(VARCHAR, primary_key=True)
    submission_date = mapped_column(Float, nullable=False)
    data = mapped_column(MutableDict.as_mutable(JSONB))


class StatsEntry(Base):
    __tablename__ = 'stats'

    name = mapped_column(VARCHAR, primary_key=True)
    data = mapped_column(MutableDict.as_mutable(JSONB), nullable=False)


class SearchCacheEntry(Base):
    __tablename__ = 'search_cache'

    uid = mapped_column(UID, primary_key=True)
    query = mapped_column(VARCHAR, nullable=False)  # the query that searches for the files that the YARA rule matched
    yara_rule = mapped_column(VARCHAR, nullable=False)


class WebInterfaceTemplateEntry(Base):
    __tablename__ = 'templates'

    plugin = mapped_column(VARCHAR, primary_key=True)
    template = mapped_column(LargeBinary, nullable=False)


class VirtualFilePath(Base):
    """Represents a file path `file_path` of file `file_object` extracted from `_parent_object`"""

    __tablename__ = 'virtual_file_path'

    parent_uid = mapped_column(UID, ForeignKey('file_object.uid', ondelete='CASCADE'), nullable=False, index=True)
    file_uid = mapped_column(UID, ForeignKey('file_object.uid', ondelete='CASCADE'), nullable=False, index=True)
    file_path = mapped_column(VARCHAR, nullable=False)

    _file_object = relationship('FileObjectEntry', uselist=False, foreign_keys=[file_uid])
    # for cascade deletion:
    _parent_object = relationship('FileObjectEntry', uselist=False, foreign_keys=[parent_uid])

    # unique constraint: each combination of parent + child + path should be unique
    __table_args__ = (PrimaryKeyConstraint('parent_uid', 'file_uid', 'file_path', name='_vfp_primary_key'),)


@event.listens_for(Session, 'persistent_to_deleted')
def delete_file_orphans(session, deleted_object):
    """
    If a firmware is deleted, delete all "orphaned" files: files that do not belong to any firmware anymore (and also
    are not a firmware themselves).
    """
    if isinstance(deleted_object, FirmwareEntry):
        session.execute(
            delete(FileObjectEntry)
            .where(~FileObjectEntry.is_firmware, ~FileObjectEntry.root_firmware.any())
            .execution_options(synchronize_session='fetch')
        )
