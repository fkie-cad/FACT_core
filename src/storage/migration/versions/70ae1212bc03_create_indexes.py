"""Create indexes

Revision ID: 70ae1212bc03
Revises: a1312300d62d
Create Date: 2023-07-13 13:58:10.188261

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '70ae1212bc03'
down_revision = 'a1312300d62d'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(op.f('ix_analysis_uid'), 'analysis', ['uid'], unique=False)
    op.create_index(op.f('ix_included_files_parent_uid'), 'included_files', ['parent_uid'], unique=False)
    op.create_index(op.f('ix_included_files_child_uid'), 'included_files', ['child_uid'], unique=False)
    op.create_index(op.f('ix_fw_files_root_uid'), 'fw_files', ['root_uid'], unique=False)
    op.create_index(op.f('ix_fw_files_file_uid'), 'fw_files', ['file_uid'], unique=False)
    op.create_index(op.f('ix_virtual_file_path_parent_uid'), 'virtual_file_path', ['parent_uid'], unique=False)
    op.create_index(op.f('ix_virtual_file_path_file_uid'), 'virtual_file_path', ['file_uid'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_analysis_uid'), table_name='analysis')
    op.drop_index(op.f('ix_included_files_parent_uid'), table_name='included_files')
    op.drop_index(op.f('ix_included_files_child_uid'), table_name='included_files')
    op.drop_index(op.f('ix_fw_files_root_uid'), table_name='fw_files')
    op.drop_index(op.f('ix_fw_files_file_uid'), table_name='fw_files')
    op.drop_index(op.f('ix_virtual_file_path_parent_uid'), table_name='virtual_file_path')
    op.drop_index(op.f('ix_virtual_file_path_file_uid'), table_name='virtual_file_path')
