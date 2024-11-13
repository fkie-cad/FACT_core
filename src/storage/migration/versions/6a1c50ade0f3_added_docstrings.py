"""Added docstrings

Revision ID: 6a1c50ade0f3
Revises: 81a549a2be95
Create Date: 2024-11-11 17:25:32.794591

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

ANALYSIS_TABLE_UID_COMMENT = 'The UID of the file object on which this analysis was performed.'
ANALYSIS_TABLE_PLUGIN_COMMENT = 'The name of the analysis plugin (e.g. "file_type").'
ANALYSIS_TABLE_VERSION_COMMENT = 'The version of the analysis plugin.'
ANALYSIS_TABLE_SYS_VER_COMMENT = (
    'The system version of the analysis plugin (may be null). '
    'This only applies to plugins relying on external tools or libraries which may change in version '
    'independently of the plugin itself (e.g. YARA).'
)
ANALYSIS_TABLE_DATE_COMMENT = 'The date the analysis was performed.'
ANALYSIS_TABLE_SUMMARY_COMMENT = (
    'The summary of the analysis. '
    'This is an array of strings which represent important results to be displayed on the analysis page of '
    'the firmware image from which the analyzed file was unpacked.'
)
ANALYSIS_TABLE_TAGS_COMMENT = (
    'A JSON object containing all tags set by the plugin during analysis. '
    'Tags can be propagated, meaning they are also displayed for the file this file was unpacked from, '
    'and all parent files up to the root file of the firmware. '
    'If not propagated, the tags are only displayed on the analysis page of the file itself.'
)
ANALYSIS_TABLE_RESULT_COMMENT = 'The result of the analysis in JSON format.'
ANALYSIS_TABLE_COMMENT = (
    'The analysis table. '
    'Each entry represents the result of an analysis plugin that was executed on a file object. '
    'This means there are individual entries not only for all files that were unpacked from a firmware '
    'but also for each plugin.'
)

FILE_TABLE_UID_COMMENT = (
    'The UID of this file object which uniquely identifies it. '
    'The UID is composed of the SHA256 hash and the size of the file.'
)
FILE_TABLE_SHA_COMMENT = 'The SHA256 hash of the file.'
FILE_TABLE_NAME_COMMENT = 'The name of the file.'
FILE_TABLE_DEPTH_COMMENT = (
    'The depth level where this file was unpacked during the recursive extraction of the firmware.'
)
FILE_TABLE_SIZE_COMMENT = 'The size of the file in bytes.'
FILE_TABLE_COMMENT_COMMENT = 'A JSON object containing all user comments on this file'
FILE_TABLE_FW_COMMENT = (
    'Whether this file represents a firmware or a file that was unpacked from one. '
    'If this is True, an according entry in the "firmware" table also exists.'
)
FILE_TABLE_COMMENT = (
    'The file object table. '
    'Each entry represents a file that was (recursively) unpacked from a firmware image. '
    'This table also includes the ("root") firmware image files that were uploaded to FACT '
    '(only for these files the value of "is_firmware" is True).'
)

FIRMWARE_TABLE_UID_COMMENT = (
    'The UID of the file object that belongs to this firmware. '
    'It represents the ("root") firmware image file from which all others are unpacked.'
)
FIRMWARE_TABLE_DATE_COMMENT = 'The date when the firmware was uploaded to FACT.'
FIRMWARE_TABLE_RELEASE_COMMENT = 'The release date of the firmware.'
FIRMWARE_TABLE_VERSION_COMMENT = 'The version of the firmware.'
FIRMWARE_TABLE_VENDOR_COMMENT = 'The vendor of the device.'
FIRMWARE_TABLE_NAME_COMMENT = 'The name of the device.'
FIRMWARE_TABLE_CLASS_COMMENT = 'The class of the device (e.g. router, access point, printer, IP cam, etc.)'
FIRMWARE_TABLE_PART_COMMENT = (
    'Which part of the firmware this entry represents (complete, kernel, bootloader, or root FS).'
)
FIRMWARE_TABLE_TAGS_COMMENT = 'Tags that were set by the user during upload.'
FIRMWARE_TABLE_COMMENT = (
    'The firmware table. Each entry represents a firmware that was uploaded to FACT. '
    'This table only contains the metadata. The actual file is represented by the "root object".'
)

FW_FILES_TABLE_ROOT_COMMENT = (
    'The UID of the root file object which represents the firmware image that was uploaded to FACT.'
)
FW_FILES_TABLE_FILE_COMMENT = (
    'The UID of the file object which was unpacked from the firmware during recursive extraction.'
)
FW_FILES_TABLE_COMMENT = (
    'A table representing the relation of a firmware and all files that were recursively unpacked from it. '
    'Both have corresponding entries in the file object table.'
)

INCLUDED_FILES_TABLE_PARENT_COMMENT = 'The UID of the parent file object from which the child was unpacked.'
INCLUDED_FILES_TABLE_CHILD_COMMENT = 'The UID of the child file object which was unpacked from the parent file object.'
INCLUDED_FILES_TABLE_COMMENT = (
    'A table representing the relation of parent files and child files which were extracted from those parent '
    'files (both entries from the file object table).'
)

VFP_TABLE_PARENT_COMMENT = 'The parent file where the file was extracted from.'
VFP_TABLE_UID_COMMENT = 'The file object that was extracted from the parent and to which the path belongs.'
VFP_TABLE_PATH_COMMENT = (
    'A file path of the file when unpacked from the parent object. '
    'This includes the name of the file and possible directories separated slashes ("/").'
)
VFP_TABLE_COMMENT = (
    'A table that describes what name and path (where applicable) a file had when if was unpacked from a '
    'parent object (e.g. an archive or file system). There can be multiple entries for the same pair of parent '
    'and file if a file was unpacked multiple times from the same parent, so only the combination of all three '
    'fields is unique.'
)

# revision identifiers, used by Alembic.
revision = '6a1c50ade0f3'
down_revision = '81a549a2be95'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        'analysis',
        'uid',
        existing_type=sa.VARCHAR(length=78),
        comment=ANALYSIS_TABLE_UID_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'analysis',
        'plugin',
        existing_type=sa.VARCHAR(length=64),
        comment=ANALYSIS_TABLE_PLUGIN_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'analysis',
        'plugin_version',
        existing_type=sa.VARCHAR(length=16),
        comment=ANALYSIS_TABLE_VERSION_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'analysis',
        'system_version',
        existing_type=sa.VARCHAR(),
        comment=ANALYSIS_TABLE_SYS_VER_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'analysis',
        'analysis_date',
        existing_type=sa.DOUBLE_PRECISION(precision=53),
        comment=ANALYSIS_TABLE_DATE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'analysis',
        'summary',
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        comment=ANALYSIS_TABLE_SUMMARY_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'analysis',
        'tags',
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        comment=ANALYSIS_TABLE_TAGS_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'analysis',
        'result',
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        comment=ANALYSIS_TABLE_RESULT_COMMENT,
        existing_nullable=True,
    )
    op.create_table_comment(
        'analysis',
        comment=ANALYSIS_TABLE_COMMENT,
        existing_comment=None,
        schema=None,
    )
    op.alter_column(
        'file_object',
        'uid',
        existing_type=sa.VARCHAR(length=78),
        comment=FILE_TABLE_UID_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'sha256',
        existing_type=sa.CHAR(length=64),
        comment=FILE_TABLE_SHA_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'file_name',
        existing_type=sa.VARCHAR(),
        comment=FILE_TABLE_NAME_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'depth',
        existing_type=sa.INTEGER(),
        comment=FILE_TABLE_DEPTH_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'size',
        existing_type=sa.BIGINT(),
        comment=FILE_TABLE_SIZE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'comments',
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        comment=FILE_TABLE_COMMENT_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'file_object',
        'is_firmware',
        existing_type=sa.BOOLEAN(),
        comment=FILE_TABLE_FW_COMMENT,
        existing_nullable=False,
    )
    op.create_table_comment(
        'file_object',
        comment=FILE_TABLE_COMMENT,
        existing_comment=None,
        schema=None,
    )
    op.alter_column(
        'firmware',
        'uid',
        existing_type=sa.VARCHAR(length=78),
        comment=FIRMWARE_TABLE_UID_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'submission_date',
        existing_type=sa.DOUBLE_PRECISION(precision=53),
        comment=FIRMWARE_TABLE_DATE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'release_date',
        existing_type=sa.DATE(),
        comment=FIRMWARE_TABLE_RELEASE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'version',
        existing_type=sa.VARCHAR(),
        comment=FIRMWARE_TABLE_VERSION_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'vendor',
        existing_type=sa.VARCHAR(),
        comment=FIRMWARE_TABLE_VENDOR_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'device_name',
        existing_type=sa.VARCHAR(),
        comment=FIRMWARE_TABLE_NAME_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'device_class',
        existing_type=sa.VARCHAR(),
        comment=FIRMWARE_TABLE_CLASS_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'device_part',
        existing_type=sa.VARCHAR(),
        comment=FIRMWARE_TABLE_PART_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'firmware_tags',
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        comment=FIRMWARE_TABLE_TAGS_COMMENT,
        existing_nullable=True,
    )
    op.create_table_comment(
        'firmware',
        FIRMWARE_TABLE_COMMENT,
        existing_comment=None,
        schema=None,
    )
    op.alter_column(
        'fw_files',
        'root_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=FW_FILES_TABLE_ROOT_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'fw_files',
        'file_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=FW_FILES_TABLE_FILE_COMMENT,
        existing_nullable=False,
    )
    op.create_table_comment(
        'fw_files',
        comment=FW_FILES_TABLE_COMMENT,
        existing_comment=None,
        schema=None,
    )
    op.alter_column(
        'included_files',
        'parent_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=INCLUDED_FILES_TABLE_PARENT_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'included_files',
        'child_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=INCLUDED_FILES_TABLE_CHILD_COMMENT,
        existing_nullable=False,
    )
    op.create_table_comment(
        'included_files',
        comment=INCLUDED_FILES_TABLE_COMMENT,
        existing_comment=None,
        schema=None,
    )
    op.alter_column(
        'virtual_file_path',
        'parent_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=VFP_TABLE_PARENT_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'virtual_file_path',
        'file_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=VFP_TABLE_UID_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'virtual_file_path',
        'file_path',
        existing_type=sa.VARCHAR(),
        comment=VFP_TABLE_PATH_COMMENT,
        existing_nullable=False,
    )
    op.create_table_comment(
        'virtual_file_path',
        comment=VFP_TABLE_COMMENT,
        existing_comment=None,
        schema=None,
    )


def downgrade() -> None:
    op.drop_table_comment(
        'virtual_file_path',
        existing_comment=VFP_TABLE_COMMENT,
        schema=None,
    )
    op.alter_column(
        'virtual_file_path',
        'file_path',
        existing_type=sa.VARCHAR(),
        comment=None,
        existing_comment=VFP_TABLE_PATH_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'virtual_file_path',
        'file_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=VFP_TABLE_UID_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'virtual_file_path',
        'parent_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=VFP_TABLE_PARENT_COMMENT,
        existing_nullable=False,
    )
    op.drop_table_comment(
        'included_files',
        existing_comment=INCLUDED_FILES_TABLE_COMMENT,
        schema=None,
    )
    op.alter_column(
        'included_files',
        'child_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=INCLUDED_FILES_TABLE_CHILD_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'included_files',
        'parent_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=INCLUDED_FILES_TABLE_PARENT_COMMENT,
        existing_nullable=False,
    )
    op.drop_table_comment(
        'fw_files',
        existing_comment=FW_FILES_TABLE_COMMENT,
        schema=None,
    )
    op.alter_column(
        'fw_files',
        'file_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=FW_FILES_TABLE_FILE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'fw_files',
        'root_uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=FW_FILES_TABLE_ROOT_COMMENT,
        existing_nullable=False,
    )
    op.drop_table_comment(
        'firmware',
        existing_comment=FIRMWARE_TABLE_COMMENT,
        schema=None,
    )
    op.alter_column(
        'firmware',
        'firmware_tags',
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        comment=None,
        existing_comment=FIRMWARE_TABLE_TAGS_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'firmware',
        'device_part',
        existing_type=sa.VARCHAR(),
        comment=None,
        existing_comment=FIRMWARE_TABLE_PART_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'device_class',
        existing_type=sa.VARCHAR(),
        comment=None,
        existing_comment=FIRMWARE_TABLE_CLASS_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'device_name',
        existing_type=sa.VARCHAR(),
        comment=None,
        existing_comment=FIRMWARE_TABLE_NAME_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'vendor',
        existing_type=sa.VARCHAR(),
        comment=None,
        existing_comment=FIRMWARE_TABLE_VENDOR_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'version',
        existing_type=sa.VARCHAR(),
        comment=None,
        existing_comment=FIRMWARE_TABLE_VERSION_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'release_date',
        existing_type=sa.DATE(),
        comment=None,
        existing_comment=FIRMWARE_TABLE_RELEASE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'submission_date',
        existing_type=sa.DOUBLE_PRECISION(precision=53),
        comment=None,
        existing_comment=FIRMWARE_TABLE_DATE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'firmware',
        'uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=FIRMWARE_TABLE_UID_COMMENT,
        existing_nullable=False,
    )
    op.drop_table_comment(
        'file_object',
        existing_comment=FILE_TABLE_COMMENT,
        schema=None,
    )
    op.alter_column(
        'file_object',
        'is_firmware',
        existing_type=sa.BOOLEAN(),
        comment=None,
        existing_comment=FILE_TABLE_FW_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'comments',
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        comment=None,
        existing_comment=FILE_TABLE_COMMENT_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'file_object',
        'size',
        existing_type=sa.BIGINT(),
        comment=None,
        existing_comment=FILE_TABLE_SIZE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'depth',
        existing_type=sa.INTEGER(),
        comment=None,
        existing_comment=FILE_TABLE_DEPTH_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'file_name',
        existing_type=sa.VARCHAR(),
        comment=None,
        existing_comment=FILE_TABLE_NAME_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'sha256',
        existing_type=sa.CHAR(length=64),
        comment=None,
        existing_comment=FILE_TABLE_SHA_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'file_object',
        'uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=FILE_TABLE_UID_COMMENT,
        existing_nullable=False,
    )
    op.drop_table_comment(
        'analysis',
        existing_comment=ANALYSIS_TABLE_COMMENT,
        schema=None,
    )
    op.alter_column(
        'analysis',
        'result',
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        comment=None,
        existing_comment=ANALYSIS_TABLE_RESULT_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'analysis',
        'tags',
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        comment=None,
        existing_comment=ANALYSIS_TABLE_TAGS_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'analysis',
        'summary',
        existing_type=postgresql.ARRAY(sa.VARCHAR()),
        comment=None,
        existing_comment=ANALYSIS_TABLE_SUMMARY_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'analysis',
        'analysis_date',
        existing_type=sa.DOUBLE_PRECISION(precision=53),
        comment=None,
        existing_comment=ANALYSIS_TABLE_DATE_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'analysis',
        'system_version',
        existing_type=sa.VARCHAR(),
        comment=None,
        existing_comment=ANALYSIS_TABLE_SYS_VER_COMMENT,
        existing_nullable=True,
    )
    op.alter_column(
        'analysis',
        'plugin_version',
        existing_type=sa.VARCHAR(length=16),
        comment=None,
        existing_comment=ANALYSIS_TABLE_VERSION_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'analysis',
        'plugin',
        existing_type=sa.VARCHAR(length=64),
        comment=None,
        existing_comment=ANALYSIS_TABLE_PLUGIN_COMMENT,
        existing_nullable=False,
    )
    op.alter_column(
        'analysis',
        'uid',
        existing_type=sa.VARCHAR(length=78),
        comment=None,
        existing_comment=ANALYSIS_TABLE_UID_COMMENT,
        existing_nullable=False,
    )
