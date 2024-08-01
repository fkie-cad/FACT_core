"""added oncascade delete for foreign keys

Revision ID: 221cfef47173
Revises:
Create Date: 2023-03-23 17:05:22.740165

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '221cfef47173'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # added ondelete='CASCADE' on ForeignKey "uid" in table "analysis":
    op.drop_constraint('analysis_uid_fkey', 'analysis', type_='foreignkey')
    op.create_foreign_key('analysis_uid_fkey', 'analysis', 'file_object', ['uid'], ['uid'], ondelete='CASCADE')

    # added ondelete='CASCADE' on ForeignKeys "parent_uid" and "child_uid" in table "included_files":
    op.drop_constraint('included_files_parent_uid_fkey', 'included_files', type_='foreignkey')
    op.drop_constraint('included_files_child_uid_fkey', 'included_files', type_='foreignkey')
    op.create_foreign_key(
        'included_files_parent_uid_fkey', 'included_files', 'file_object', ['parent_uid'], ['uid'], ondelete='CASCADE'
    )
    op.create_foreign_key(
        'included_files_child_uid_fkey', 'included_files', 'file_object', ['child_uid'], ['uid'], ondelete='CASCADE'
    )

    # added ondelete='CASCADE' on ForeignKeys "parent_uid" and "child_uid" in table "included_files":
    op.drop_constraint('fw_files_file_uid_fkey', 'fw_files', type_='foreignkey')
    op.create_foreign_key(
        'fw_files_file_uid_fkey', 'fw_files', 'file_object', ['file_uid'], ['uid'], ondelete='CASCADE'
    )
    op.drop_constraint('fw_files_root_uid_fkey', 'fw_files', type_='foreignkey')
    op.create_foreign_key(
        'fw_files_root_uid_fkey', 'fw_files', 'file_object', ['root_uid'], ['uid'], ondelete='CASCADE'
    )

    # added ondelete='CASCADE' on ForeignKeys "parent_uid" and "child_uid" in table "included_files":
    op.drop_constraint('compared_files_file_uid_fkey', 'compared_files', type_='foreignkey')
    op.create_foreign_key(
        'compared_files_file_uid_fkey', 'compared_files', 'file_object', ['file_uid'], ['uid'], ondelete='CASCADE'
    )
    op.drop_constraint('compared_files_comparison_id_fkey', 'compared_files', type_='foreignkey')
    op.create_foreign_key(
        'compared_files_comparison_id_fkey',
        'compared_files',
        'comparison',
        ['comparison_id'],
        ['comparison_id'],
        ondelete='CASCADE',
    )

    # added ondelete='CASCADE' on ForeignKey "uid" in table "firmware":
    op.drop_constraint('firmware_uid_fkey', 'firmware', type_='foreignkey')
    op.create_foreign_key('firmware_uid_fkey', 'firmware', 'file_object', ['uid'], ['uid'], ondelete='CASCADE')


def downgrade():
    op.drop_constraint('included_files_child_uid_fkey', 'included_files', type_='foreignkey')
    op.create_foreign_key('included_files_child_uid_fkey', 'included_files', 'file_object', ['child_uid'], ['uid'])
    op.drop_constraint('included_files_parent_uid_fkey', 'included_files', type_='foreignkey')
    op.create_foreign_key('included_files_parent_uid_fkey', 'included_files', 'file_object', ['parent_uid'], ['uid'])

    op.drop_constraint('fw_files_root_uid_fkey', 'fw_files', type_='foreignkey')
    op.create_foreign_key('fw_files_root_uid_fkey', 'fw_files', 'file_object', ['root_uid'], ['uid'])
    op.drop_constraint('fw_files_file_uid_fkey', 'fw_files', type_='foreignkey')
    op.create_foreign_key('fw_files_file_uid_fkey', 'fw_files', 'file_object', ['file_uid'], ['uid'])

    op.drop_constraint('firmware_uid_fkey', 'firmware', type_='foreignkey')
    op.create_foreign_key('firmware_uid_fkey', 'firmware', 'file_object', ['uid'], ['uid'])

    op.drop_constraint('compared_files_comparison_id_fkey', 'compared_files', type_='foreignkey')
    op.create_foreign_key(
        'compared_files_comparison_id_fkey', 'compared_files', 'comparison', ['comparison_id'], ['comparison_id']
    )
    op.drop_constraint('compared_files_file_uid_fkey', 'compared_files', type_='foreignkey')
    op.create_foreign_key('compared_files_file_uid_fkey', 'compared_files', 'file_object', ['file_uid'], ['uid'])

    op.drop_constraint('analysis_uid_fkey', 'analysis', type_='foreignkey')
    op.create_foreign_key('analysis_uid_fkey', 'analysis', 'file_object', ['uid'], ['uid'])
