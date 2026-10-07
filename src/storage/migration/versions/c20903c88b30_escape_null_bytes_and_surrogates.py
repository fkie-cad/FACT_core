"""Escape null bytes and surrogates in existing data

Revision ID: c20903c88b30
Revises: 6a1c50ade0f3
Create Date: 2026-08-27 17:20:36

"""

from __future__ import annotations

import logging

from alembic import op
from sqlalchemy import Column, ForeignKey, orm, select
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, VARCHAR
from sqlalchemy.orm import declarative_base

from storage.safe_types import _escape_json, _escape_string, _strip_unsafe_chars, _unescape_json, _unescape_string

# revision identifiers, used by Alembic.
revision = 'c20903c88b30'
down_revision = '6a1c50ade0f3'
branch_labels = None
depends_on = None

Base = declarative_base()
UID = VARCHAR(78)

# Plain (non-Safe) models: the escape function is applied manually so that existing data is not escaped twice.


class AnalysisEntry(Base):
    __tablename__ = 'analysis'

    uid = Column(UID, ForeignKey('file_object.uid'), primary_key=True)
    plugin = Column(VARCHAR(64), primary_key=True)
    summary = Column(ARRAY(VARCHAR))
    tags = Column(JSONB)
    result = Column(JSONB)


class FirmwareEntry(Base):
    __tablename__ = 'firmware'

    uid = Column(UID, ForeignKey('file_object.uid'), primary_key=True)
    firmware_tags = Column(ARRAY(VARCHAR))


class ComparisonEntry(Base):
    __tablename__ = 'comparison'

    comparison_id = Column(VARCHAR, primary_key=True)
    data = Column(JSONB)


class StatsEntry(Base):
    __tablename__ = 'stats'

    name = Column(VARCHAR, primary_key=True)
    data = Column(JSONB, nullable=False)


class SearchCacheEntry(Base):
    __tablename__ = 'search_cache'

    uid = Column(UID, primary_key=True)
    match_data = Column(JSONB)


def upgrade() -> None:
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    _escape_analysis_entries(session)
    _escape_firmware_tags(session)
    _escape_comparison_data(session)
    _escape_stats_data(session)
    _escape_search_cache(session)

    session.commit()


def _escape_analysis_entries(session: orm.Session) -> None:
    query = select(AnalysisEntry)
    for entry in session.execute(query.execution_options(yield_per=1000)).scalars():
        if entry.result is not None:
            _escape_json_field(entry, 'result')
        if entry.tags is not None:
            _escape_json_field(entry, 'tags')
        if entry.summary is not None:
            _escape_list_field(entry, 'summary')
        _flush_and_release(session, entry)


def _escape_firmware_tags(session: orm.Session) -> None:
    for entry in session.execute(select(FirmwareEntry).execution_options(yield_per=1000)).scalars():
        if entry.firmware_tags is not None:
            _escape_list_field(entry, 'firmware_tags')
        _flush_and_release(session, entry)


def _escape_comparison_data(session: orm.Session) -> None:
    for entry in session.execute(select(ComparisonEntry).execution_options(yield_per=1000)).scalars():
        if entry.data is not None:
            _escape_json_field(entry, 'data')
        _flush_and_release(session, entry)


def _escape_stats_data(session: orm.Session) -> None:
    for entry in session.execute(select(StatsEntry).execution_options(yield_per=1000)).scalars():
        _escape_json_field(entry, 'data')
        _flush_and_release(session, entry)


def _escape_search_cache(session: orm.Session) -> None:
    for entry in session.execute(select(SearchCacheEntry).execution_options(yield_per=1000)).scalars():
        if entry.match_data is not None:
            _escape_json_field(entry, 'match_data')
        _flush_and_release(session, entry)


def _escape_json_field(entry: object, attribute: str) -> None:
    value = getattr(entry, attribute)
    if _unescape_json(value) != value:
        setattr(entry, attribute, _escape_json(value))


def _escape_list_field(entry: object, attribute: str) -> None:
    value = getattr(entry, attribute)
    escaped = [_escape_string(s) for s in value]
    if escaped != value:
        setattr(entry, attribute, escaped)


def _flush_and_release(session: orm.Session, entry: object) -> None:
    session.flush()
    session.expunge(entry)


def downgrade() -> None:
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    _unescape_analysis_entries(session)
    _unescape_firmware_tags(session)
    _unescape_comparison_data(session)
    _unescape_stats_data(session)
    _unescape_search_cache(session)

    session.commit()


def _unescape_analysis_entries(session: orm.Session) -> None:
    for entry in session.execute(select(AnalysisEntry).execution_options(yield_per=1000)).scalars():
        if entry.result is not None:
            _unescape_json_field(entry, 'result')
        if entry.tags is not None:
            _unescape_json_field(entry, 'tags')
        if entry.summary is not None:
            _unescape_list_field(entry, 'summary')
        _flush_and_release(session, entry)


def _unescape_firmware_tags(session: orm.Session) -> None:
    for entry in session.execute(select(FirmwareEntry).execution_options(yield_per=1000)).scalars():
        if entry.firmware_tags is not None:
            _unescape_list_field(entry, 'firmware_tags')
        _flush_and_release(session, entry)


def _unescape_comparison_data(session: orm.Session) -> None:
    for entry in session.execute(select(ComparisonEntry).execution_options(yield_per=1000)).scalars():
        if entry.data is not None:
            _unescape_json_field(entry, 'data')
        _flush_and_release(session, entry)


def _unescape_stats_data(session: orm.Session) -> None:
    for entry in session.execute(select(StatsEntry).execution_options(yield_per=1000)).scalars():
        _unescape_json_field(entry, 'data')
        _flush_and_release(session, entry)


def _unescape_search_cache(session: orm.Session) -> None:
    for entry in session.execute(select(SearchCacheEntry).execution_options(yield_per=1000)).scalars():
        if entry.match_data is not None:
            _unescape_json_field(entry, 'match_data')
        _flush_and_release(session, entry)


def _unescape_json_field(entry: object, attribute: str) -> None:
    value = getattr(entry, attribute)
    unescaped = _unescape_json(value)
    stripped = _strip_unsafe_chars(unescaped)
    if stripped != unescaped:
        logging.warning(f'Stripped null bytes/surrogates from {type(entry).__name__}.{attribute} during downgrade')
    if stripped != value:
        setattr(entry, attribute, stripped)


def _unescape_list_field(entry: object, attribute: str) -> None:
    value = getattr(entry, attribute)
    unescaped = [_unescape_string(s) for s in value]
    stripped = [_strip_unsafe_chars(s) for s in unescaped]
    if stripped != unescaped:
        logging.warning(f'Stripped null bytes/surrogates from {type(entry).__name__}.{attribute} during downgrade')
    if stripped != value:
        setattr(entry, attribute, stripped)
