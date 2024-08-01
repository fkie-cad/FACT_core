from __future__ import annotations

from json import dumps
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import func, or_, select, type_coerce
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import aliased

from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry

if TYPE_CHECKING:
    from sqlalchemy.sql import Select

FIRMWARE_ORDER = FirmwareEntry.vendor.asc(), FirmwareEntry.device_name.asc()


class QueryConversionException(Exception):  # noqa: N818
    def get_message(self):
        if self.args:
            return self.args[0]
        return ''


def build_generic_search_query(search_dict: dict, only_fo_parent_firmware: bool, inverted: bool) -> Select:
    if search_dict == {}:
        return select(FirmwareEntry).order_by(*FIRMWARE_ORDER)

    if only_fo_parent_firmware:
        return query_parent_firmware(search_dict, inverted)

    return build_query_from_dict(search_dict).order_by(FileObjectEntry.file_name.asc())


def query_parent_firmware(search_dict: dict, inverted: bool, count: bool = False) -> Select:
    # define alias so that FileObjectEntry can be referenced twice in query
    root_fo = aliased(FileObjectEntry, name='root_fo')
    base_query = (
        select(root_fo.uid)
        # explicitly state FROM because FileObjectEntry is not in select
        .select_from(root_fo, FileObjectEntry)
        # root_fo is in parent_firmware of the FO or FO is the "root file object" of the root_fo
        .filter(FileObjectEntry.root_firmware.any(uid=root_fo.uid) | (FileObjectEntry.uid == root_fo.uid))
    )
    query = build_query_from_dict(search_dict, query=base_query)

    query_filter = FirmwareEntry.uid.notin_(query) if inverted else FirmwareEntry.uid.in_(query)

    if count:
        return select(func.count(FirmwareEntry.uid)).filter(query_filter)
    return select(FirmwareEntry).filter(query_filter).order_by(*FIRMWARE_ORDER)


def build_query_from_dict(  # noqa: C901, PLR0912
    query_dict: dict,
    query: Select | None = None,
    fw_only: bool = False,
    or_query: bool = False,
) -> Select:
    """
    Builds an ``sqlalchemy.orm.Query`` object from a query in dict form.
    """
    if query is None:
        query = select(FileObjectEntry) if not fw_only else select(FirmwareEntry)
    filters = []

    if '$or' in query_dict:  # insert inception reference here
        return build_query_from_dict(query_dict['$or'], query, fw_only=fw_only, or_query=True)

    if '_id' in query_dict:
        # FixMe?: backwards compatible for binary search
        query_dict['uid'] = query_dict.pop('_id')

    analysis_search_dict = {key: value for key, value in query_dict.items() if key.startswith('processed_analysis')}
    if analysis_search_dict:
        query = query.join(
            AnalysisEntry, AnalysisEntry.uid == (FileObjectEntry.uid if not fw_only else FirmwareEntry.uid)
        )
        for key, value in analysis_search_dict.items():
            _, plugin, subkey = key.split('.', maxsplit=2)
            filters.append((_add_analysis_filter_to_query(key, value, subkey)) & (AnalysisEntry.plugin == plugin))

    firmware_search_dict = get_search_keys_from_dict(query_dict, FirmwareEntry, blacklist=['uid'])
    if firmware_search_dict:
        if not fw_only:
            join_function = (
                query.outerjoin if or_query else query.join
            )  # outer join in case of "$or" so file objects still match
            query = join_function(FirmwareEntry, FirmwareEntry.uid == FileObjectEntry.uid)
        for key, value in firmware_search_dict.items():
            if key == 'firmware_tags':  # special case: array field
                filters.append(_get_array_filter(FirmwareEntry.firmware_tags, key, value))
            else:
                filters.append(_dict_key_to_filter(_get_column(key, FirmwareEntry), key, value))

    file_search_dict = get_search_keys_from_dict(query_dict, FileObjectEntry)
    if file_search_dict:
        if fw_only:  # join on uid here, so we only match the root file objects
            query = query.join(FileObjectEntry, FirmwareEntry.uid == FileObjectEntry.uid)
        for key, value in file_search_dict.items():
            filters.append(_dict_key_to_filter(_get_column(key, FileObjectEntry), key, value))

    query = query.filter(or_(*filters)) if or_query else query.filter(*filters)

    return query.distinct()


def get_search_keys_from_dict(query_dict: dict, table, blacklist: Optional[list[str]] = None) -> dict[str, Any]:
    return {key: value for key, value in query_dict.items() if key not in (blacklist or []) and hasattr(table, key)}


def _dict_key_to_filter(column, key: str, value: Any):  # noqa: PLR0911
    if not isinstance(value, dict):
        return column == value
    if '$exists' in value:
        return column.has_key(key.split('.')[-1])
    if '$regex' in value:
        return column.op('~')(value['$regex'])
    if '$like' in value:  # match substring ignoring case
        return column.ilike(f'%{value["$like"]}%')
    if '$in' in value:  # filter by list
        return column.in_(value['$in'])
    if '$ne' in value:  # not equal
        return column != value['$ne']
    if '$lt' in value:  # less than
        return column < value['$lt']
    if '$gt' in value:  # greater than
        return column > value['$gt']
    if '$contains' in value:  # array contains value
        return column.contains(value['$contains'])
    raise QueryConversionException(f'Search options currently unsupported: {value}')


def _get_column(key: str, table: type[FirmwareEntry] | type[FileObjectEntry] | type[AnalysisEntry]):
    column = getattr(table, key)
    if key == 'release_date':  # special case: Date column -> convert to string
        return func.to_char(column, 'YYYY-MM-DD')
    return column


def _add_analysis_filter_to_query(key: str, value: Any, subkey: str):
    if hasattr(AnalysisEntry, subkey):
        if subkey == 'summary':  # special case: array field
            return _get_array_filter(AnalysisEntry.summary, key, value)
        return getattr(AnalysisEntry, subkey) == value
    # no metadata field, actual analysis result key in `AnalysisEntry.result` (JSON)
    return _add_json_filter(key, value, subkey)


def _get_array_filter(field, key, value):
    if isinstance(value, list):  # array can be queried with list or single value
        return field.contains(value)
    if isinstance(value, dict):
        if '$regex' in value:  # array + "$regex" needs a trick: convert array to string
            column = func.array_to_string(field, ',')
            return _dict_key_to_filter(column, key, value)
        if '$contains' in value:
            return field.contains(_to_list(value['$contains']))
        if '$overlap' in value:
            return field.overlap(_to_list(value['$overlap']))
        raise QueryConversionException(f'Unsupported search option for ARRAY field: {value}')
    return field.contains([value])  # filter by value


def _to_list(value):
    return value if isinstance(value, list) else [value]


def _add_json_filter(key, value, subkey):
    column = AnalysisEntry.result
    if isinstance(value, dict) and '$exists' in value:
        # "$exists" (aka key exists in json document) is a special case because
        # we need to query the element one level above the actual key
        for nested_key in subkey.split('.')[:-1]:
            column = column[nested_key]
    else:
        for nested_key in subkey.split('.'):
            column = column[nested_key]

    if isinstance(value, dict):
        for key_, value_ in value.items():
            if key_ in ['$in', '$like']:
                column = column.astext
                break
            value[key_] = dumps(value_)
    else:
        value = type_coerce(value, JSONB)
    return _dict_key_to_filter(column, key, value)
