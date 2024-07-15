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

    uid = mapped_column(
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        index=True,
        comment='The UID of the file object on which this analysis was performed.',
    )
    plugin = mapped_column(
        VARCHAR(64),
        nullable=False,
        comment='The name of the analysis plugin (e.g. "file_type").',
    )
    plugin_version = mapped_column(
        VARCHAR(16),
        nullable=False,
        comment='The version of the analysis plugin.',
    )
    system_version = mapped_column(
        VARCHAR,
        comment=(
            'The system version of the analysis plugin (may be null). This only applies to plugins relying on external '
            'tools or libraries which may change in version independently of the plugin itself (e.g. YARA).'
        ),
    )
    analysis_date = mapped_column(
        Float,
        nullable=False,
        comment='The date the analysis was performed.',
    )
    summary = mapped_column(
        ARRAY(VARCHAR, dimensions=1),
        nullable=True,
        comment=(
            'The summary of the analysis. This is an array of strings which represent important results to be'
            'displayed on the analysis page of the firmware image from which the analyzed file was unpacked.'
        ),
    )
    tags = mapped_column(
        MutableDict.as_mutable(JSONB),
        nullable=True,
        comment=(
            'A JSON object containing all tags set by the plugin during analysis. Tags can be propagated, meaning they '
            'are also displayed for the file this file was unpacked from, and all parent files up to the root file of '
            'the firmware. If not propagated, the tags are only displayed on the analysis page of the file itself.'
        ),
    )
    result = mapped_column(
        MutableDict.as_mutable(JSONB),
        nullable=True,
        comment='The result of the analysis in JSON format.',
    )

    file_object = relationship(
        'FileObjectEntry',
        back_populates='analyses',
    )

    __table_args__ = (
        PrimaryKeyConstraint(
            'uid',
            'plugin',
            name='_analysis_primary_key',
        ),
        Index(
            'result_gin_index',
            'result',
            postgresql_using='gin',
        ),
        {
            'comment': (
                'The analysis table. Each entry represents the result of an analysis plugin that was executed on a '
                'file object. This means there are individual entries not only for all files that were unpacked from '
                'a firmware but also for each plugin.'
            )
        },
    )

    def __repr__(self) -> str:
        return f'AnalysisEntry({self.uid}, {self.plugin}, {self.plugin_version})'


included_files_table = Table(
    'included_files',
    Base.metadata,
    Column(
        'parent_uid',
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        primary_key=True,
        index=True,
        comment='The UID of the parent file object from which the child was unpacked.',
    ),
    Column(
        'child_uid',
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        primary_key=True,
        index=True,
        comment='The UID of the child file object which was unpacked from the parent file object.',
    ),
    comment=(
        'A table representing the relation of parent files and child files which were extracted from those parent '
        'files (both entries from the file object table).'
    ),
)

fw_files_table = Table(
    'fw_files',
    Base.metadata,
    Column(
        'root_uid',
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        primary_key=True,
        index=True,
        comment='The UID of the root file object which represents the firmware image that was uploaded to FACT.',
    ),
    Column(
        'file_uid',
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        primary_key=True,
        index=True,
        comment='The UID of the file object which was unpacked from the firmware during recursive extraction.',
    ),
    comment=(
        'A table representing the relation of a firmware and all files that were recursively unpacked from it. Both '
        'have corresponding entries in the file object table.'
    ),
)

comparisons_table = Table(
    'compared_files',
    Base.metadata,
    Column(
        'comparison_id',
        VARCHAR,
        ForeignKey('comparison.comparison_id', ondelete='CASCADE'),
        primary_key=True,
    ),
    Column(
        'file_uid',
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        primary_key=True,
    ),
)


class FileObjectEntry(Base):
    __tablename__ = 'file_object'
    __table_args__ = (
        {
            'comment': (
                'The file object table. Each entry represents a file that was (recursively) unpacked from a firmware '
                'image. This table also includes the ("root") firmware image files that were uploaded to FACT (only '
                'for these files the value of "is_firmware" is True).'
            )
        },
    )

    uid = mapped_column(
        UID,
        primary_key=True,
        comment=(
            'The UID of this file object which uniquely identifies it. The UID is composed of the SHA256 hash and the '
            'size of the file.'
            # FixMe? implying the sha256 is not unique enough lol; maybe we should merge this and the sha256 column
        ),
    )
    sha256 = mapped_column(
        CHAR(64),
        nullable=False,
        comment='The SHA256 hash of the file.',
    )
    file_name = mapped_column(
        VARCHAR,
        nullable=False,
        comment='The name of the file.',
    )
    depth = mapped_column(
        Integer,
        nullable=False,
        comment='The depth level where this file was unpacked during the recursive extraction of the firmware.',
    )
    size = mapped_column(
        BigInteger,
        nullable=False,
        comment='The size of the file in bytes.',
    )
    comments = mapped_column(
        MutableList.as_mutable(JSONB),
        comment='A JSON object containing all user comments on this file',
    )
    is_firmware = mapped_column(
        Boolean,
        nullable=False,
        comment=(
            'Whether this file represents a firmware or a file that was unpacked from one. If this is True, an '
            'according entry in the "firmware" table also exists.'
        ),
    )

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
    __table_args__ = (
        {
            'comment': (
                'The firmware table. Each entry represents a firmware that was uploaded to FACT. This table only '
                'contains the metadata. The actual file is represented by the "root object".'
            )
        },
    )

    uid = mapped_column(
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        primary_key=True,
        comment=(
            'The UID of the file object that belongs to this firmware. It represents the ("root") firmware image file '
            'from which all others are unpacked.'
        ),
    )
    submission_date = mapped_column(
        Float,
        nullable=False,
        comment='The date when the firmware was uploaded to FACT.',
    )
    release_date = mapped_column(
        Date,
        nullable=False,
        comment='The release date of the firmware.',
    )
    version = mapped_column(
        VARCHAR,
        nullable=False,
        comment='The version of the firmware.',
    )
    vendor = mapped_column(
        VARCHAR,
        nullable=False,
        comment='The vendor of the device.',
    )
    device_name = mapped_column(
        VARCHAR,
        nullable=False,
        comment='The name of the device.',
    )
    device_class = mapped_column(
        VARCHAR,
        nullable=False,
        comment='The class of the device (e.g. router, access point, printer, IP cam, etc.)',
    )
    device_part = mapped_column(
        VARCHAR,
        nullable=False,
        comment='Which part of the firmware this entry represents (complete, kernel, bootloader, or root FS).',
    )
    firmware_tags = mapped_column(
        ARRAY(VARCHAR, dimensions=1),
        comment='Tags that were set by the user during upload.',
    )

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
    match_data = mapped_column(MutableDict.as_mutable(JSONB), nullable=True)


class WebInterfaceTemplateEntry(Base):
    __tablename__ = 'templates'

    plugin = mapped_column(VARCHAR, primary_key=True)
    template = mapped_column(LargeBinary, nullable=False)


class VirtualFilePath(Base):
    """Represents a file path `file_path` of file `file_object` extracted from `_parent_object`"""

    __tablename__ = 'virtual_file_path'

    parent_uid = mapped_column(
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment='The parent file where the file was extracted from.',
    )
    file_uid = mapped_column(
        UID,
        ForeignKey('file_object.uid', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment='The file object that was extracted from the parent and to which the path belongs.',
    )
    file_path = mapped_column(
        VARCHAR,
        nullable=False,
        comment=(
            'A file path of the file when unpacked from the parent object. This includes the name of the file and '
            'possible directories separated slashes ("/").'
        ),
    )

    _file_object = relationship(
        'FileObjectEntry',
        uselist=False,
        foreign_keys=[file_uid],
    )
    # for cascade deletion:
    _parent_object = relationship(
        'FileObjectEntry',
        uselist=False,
        foreign_keys=[parent_uid],
    )

    __table_args__ = (
        # unique constraint: each combination of parent + child + path should be unique
        PrimaryKeyConstraint(
            'parent_uid',
            'file_uid',
            'file_path',
            name='_vfp_primary_key',
        ),
        {
            'comment': (
                'A table that describes what name and path (where applicable) a file had when if was unpacked from '
                'a parent object (e.g. an archive or file system). There can be multiple entries for the same pair of '
                'parent and file if a file was unpacked multiple times from the same parent, so only the combination '
                'of all three fields is unique.'
            )
        },
    )


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
