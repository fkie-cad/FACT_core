"""add VFP table

Revision ID: a1312300d62d
Revises: 221cfef47173
Create Date: 2023-04-28 14:57:12.541876

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import BigInteger, Boolean, Column, ForeignKey, Integer, orm, PrimaryKeyConstraint, select, Table, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import CHAR, JSONB, VARCHAR
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import declarative_base, mapped_column

# revision identifiers, used by Alembic.
revision = 'a1312300d62d'
down_revision = '221cfef47173'
branch_labels = None
depends_on = None

Base = declarative_base()
UID = VARCHAR(78)


class FileObjectEntry(Base):
    # old FileObjectEntry with virtual_file_paths as JSONB
    # relationships can be omitted during the migration
    __tablename__ = 'file_object'

    uid = Column(UID, primary_key=True)
    sha256 = Column(CHAR(64), nullable=False)
    file_name = Column(VARCHAR, nullable=False)
    depth = Column(Integer, nullable=False)
    size = Column(BigInteger, nullable=False)
    comments = Column(MutableList.as_mutable(JSONB))
    virtual_file_paths = Column(MutableDict.as_mutable(JSONB))
    is_firmware = Column(Boolean, nullable=False)


class VirtualFilePath(Base):
    # new VirtualFilePath table to replace contents of FileObjectEntry.virtual_file_paths
    __tablename__ = 'virtual_file_path'

    parent_uid = mapped_column(UID, ForeignKey('file_object.uid', ondelete='CASCADE'), nullable=False)
    file_uid = mapped_column(UID, ForeignKey('file_object.uid', ondelete='CASCADE'), nullable=False)
    file_path = mapped_column(VARCHAR, nullable=False)

    __table_args__ = (PrimaryKeyConstraint('parent_uid', 'file_uid', 'file_path', name='_vfp_primary_key'),)


included_files_table = Table(
    'included_files',
    Base.metadata,
    Column('parent_uid', UID, ForeignKey('file_object.uid', ondelete='CASCADE'), primary_key=True),
    Column('child_uid', UID, ForeignKey('file_object.uid', ondelete='CASCADE'), primary_key=True),
)


def upgrade() -> None:
    # Create new virtual file path table
    op.create_table(
        'virtual_file_path',
        sa.Column('parent_uid', sa.VARCHAR(length=78), nullable=False),
        sa.Column('file_uid', sa.VARCHAR(length=78), nullable=False),
        sa.Column('file_path', sa.VARCHAR(), nullable=False),
        sa.ForeignKeyConstraint(['file_uid'], ['file_object.uid'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['parent_uid'], ['file_object.uid'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('parent_uid', 'file_uid', 'file_path', name='_vfp_primary_key'),
    )

    # migrate entries from FileObjectEntry.virtual_file_paths to the new table
    _create_vfp_table_entries()

    # grant privileges on new table
    _grant_privileges()

    # remove the now unused virtual_file_paths column from FileObjectEntry
    op.drop_column('file_object', 'virtual_file_paths')


def _create_vfp_table_entries():
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    query = select(FileObjectEntry.uid, FileObjectEntry.virtual_file_paths)
    for uid, vfp_dict in session.execute(query):
        vfp_entries = []
        for vfp_list in vfp_dict.values():
            for virtual_path in vfp_list:
                elements = [e for e in virtual_path.split('|') if e]
                if len(elements) < 2:  # noqa: PLR2004
                    continue  # we skip firmware VFP entries (without parent)
                *_, parent_uid, path = elements
                vfp_entries.append(VirtualFilePath(parent_uid=parent_uid, file_uid=uid, file_path=path))
        if vfp_entries:
            session.add_all(vfp_entries)
    session.commit()


USER_PRIVILEGES = [
    ('fact_user_ro', ['SELECT']),
    ('fact_user_rw', ['INSERT', 'SELECT', 'UPDATE']),
    ('fact_user_del', ['INSERT', 'SELECT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']),
]


def _grant_privileges():
    bind = op.get_bind()
    session = orm.Session(bind=bind)
    for user, privilege_list in USER_PRIVILEGES:
        for privilege in privilege_list:
            session.execute(text(f'GRANT {privilege} ON TABLE {VirtualFilePath.__tablename__} TO {user};'))


def downgrade() -> None:
    # add back old JSONB column FileObjectEntry.virtual_file_paths
    op.add_column(
        'file_object',
        sa.Column('virtual_file_paths', postgresql.JSONB(astext_type=sa.Text()), autoincrement=False, nullable=True),
    )

    # migrate entries of VirtualFilePath back to FileObjectEntry.virtual_file_paths
    _downgrade_vfp_entries()

    # remove VirtualFilePath table
    op.drop_table('virtual_file_path')


def _downgrade_vfp_entries():
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    child_to_parents = {}
    for parent, child in session.execute(select(included_files_table.c.parent_uid, included_files_table.c.child_uid)):
        child_to_parents.setdefault(child, set()).add(parent)

    full_paths = {uid: _generate_full_path(uid, child_to_parents) for uid in child_to_parents}

    root_uids = set()
    for uid, uid_path_list in full_paths.items():
        query = select(VirtualFilePath.file_path, VirtualFilePath.parent_uid).filter(VirtualFilePath.file_uid == uid)
        path_dict = {}
        for path, parent_uid in session.execute(query):
            path_dict.setdefault(parent_uid, []).append(path)

        vfp_dict = {}
        for uid_list in uid_path_list:
            root_uid, parent_uid = uid_list[0], uid_list[-2]
            root_uids.add(root_uid)
            vfp_dict.setdefault(root_uid, [])
            for path in path_dict[parent_uid]:
                vfp_dict[root_uid].append('|'.join(uid_list[:-1] + [path]))

        fo_entry = session.get(FileObjectEntry, uid)
        fo_entry.virtual_file_paths = vfp_dict

    # VFP entries of root objects still need to be updated because they have no entries in the VirtualFilePath table
    for uid in root_uids:
        fo_entry = session.get(FileObjectEntry, uid)
        fo_entry.virtual_file_paths = {uid: [uid]}

    session.commit()


def _generate_full_path(uid: str, child_to_parents: dict[str, set[str]]) -> list[list[str]]:
    return [
        [*path, uid]
        for parent in child_to_parents.get(uid, [])
        for path in (_generate_full_path(parent, child_to_parents) if parent in child_to_parents else [[parent]])
    ]
