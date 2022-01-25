from typing import Any, Dict, List, Optional, Union

from sqlalchemy import func, select
from sqlalchemy.orm import aliased
from sqlalchemy.sql import Select

from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry

FIRMWARE_ORDER = FirmwareEntry.vendor.asc(), FirmwareEntry.device_name.asc()


class QueryConversionException(Exception):
    def get_message(self):
        if self.args:  # pylint: disable=using-constant-test
            return self.args[0]  # pylint: disable=unsubscriptable-object
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

    if inverted:
        query_filter = FirmwareEntry.uid.notin_(query)
    else:
        query_filter = FirmwareEntry.uid.in_(query)

    if count:
        return select(func.count(FirmwareEntry.uid)).filter(query_filter)
    return select(FirmwareEntry).filter(query_filter).order_by(*FIRMWARE_ORDER)


def build_query_from_dict(query_dict: dict, query: Optional[Select] = None, fw_only: bool = False) -> Select:  # pylint: disable=too-complex
    '''
    Builds an ``sqlalchemy.orm.Query`` object from a query in dict form.
    '''
    if query is None:
        query = select(FileObjectEntry) if not fw_only else select(FirmwareEntry)

    if '_id' in query_dict:
        # FixMe?: backwards compatible for binary search
        query_dict['uid'] = query_dict.pop('_id')

    analysis_search_dict = {key: value for key, value in query_dict.items() if key.startswith('processed_analysis')}
    if analysis_search_dict:
        query = query.join(AnalysisEntry, AnalysisEntry.uid == (FileObjectEntry.uid if not fw_only else FirmwareEntry.uid))
        query = _add_analysis_filter_to_query(analysis_search_dict, query)

    firmware_search_dict = get_search_keys_from_dict(query_dict, FirmwareEntry, blacklist=['uid'])
    if firmware_search_dict:
        if not fw_only:
            query = query.join(FirmwareEntry, FirmwareEntry.uid == FileObjectEntry.uid)
        query = _add_filters_for_attribute_list(firmware_search_dict, FirmwareEntry, query)

    file_search_dict = get_search_keys_from_dict(query_dict, FileObjectEntry)
    if file_search_dict:
        if fw_only:
            query = query.join(FileObjectEntry, FirmwareEntry.uid == FileObjectEntry.uid)
        query = _add_filters_for_attribute_list(file_search_dict, FileObjectEntry, query)

    return query


def get_search_keys_from_dict(query_dict: dict, table, blacklist: List[str] = None) -> Dict[str, Any]:
    return {
        key: value for key, value in query_dict.items()
        if key not in (blacklist or []) and hasattr(table, key)
    }


def _add_filters_for_attribute_list(search_key_dict: dict, table, query: Select) -> Select:
    for key, value in search_key_dict.items():
        column = _get_column(key, table)
        query = query.filter(_dict_key_to_filter(column, key, value))
    return query


def _dict_key_to_filter(column, key: str, value: Any):  # pylint: disable=too-complex,too-many-return-statements
    if not isinstance(value, dict):
        return column == value
    if '$exists' in value:
        return column.has_key(key.split('.')[-1])
    if '$regex' in value:
        return column.op('~')(value['$regex'])
    if '$in' in value:  # filter by list
        return column.in_(value['$in'])
    if '$lt' in value:  # less than
        return column < value['$lt']
    if '$gt' in value:  # greater than
        return column > value['$gt']
    if '$contains' in value:  # array contains value
        return column.contains(value['$contains'])
    raise QueryConversionException(f'Search options currently unsupported: {value}')


def _get_column(key: str, table: Union[FirmwareEntry, FileObjectEntry, AnalysisEntry]):
    column = getattr(table, key)
    if key == 'release_date':  # special case: Date column -> convert to string
        return func.to_char(column, 'YYYY-MM-DD')
    return column


def _add_analysis_filter_to_query(analysis_search_dict: dict, query: Select) -> Select:
    for key, value in analysis_search_dict.items():  # type: str, Any
        _, plugin, subkey = key.split('.', maxsplit=2)
        query = query.filter(AnalysisEntry.plugin == plugin)
        if hasattr(AnalysisEntry, subkey):
            if subkey == 'summary':  # special case: array field
                query = _add_summary_filter(query, key, value)
            else:
                query = query.filter(getattr(AnalysisEntry, subkey) == value)
        else:  # no metadata field, actual analysis result key in `AnalysisEntry.result` (JSON)
            query = _add_json_filter(query, key, value, subkey)
    return query


def _add_summary_filter(query, key, value):
    if isinstance(value, list):  # array can be queried with list or single value
        query = query.filter(AnalysisEntry.summary.contains(value))
    elif isinstance(value, dict):
        if '$regex' in value:  # array + "$regex" needs a trick: convert array to string
            column = func.array_to_string(AnalysisEntry.summary, ',')
            query = query.filter(_dict_key_to_filter(column, key, value))
        else:
            raise QueryConversionException(f'Unsupported search option for ARRAY field: {value}')
    else:  # value
        query = query.filter(AnalysisEntry.summary.contains([value]))
    return query


def _add_json_filter(query, key, value, subkey):
    column = AnalysisEntry.result
    if '$exists' in value:
        # "$exists" (aka key exists in json document) is a special case because
        # we need to query the element one level above the actual key
        for nested_key in subkey.split('.')[:-1]:
            column = column[nested_key]
    else:
        for nested_key in subkey.split('.'):
            column = column[nested_key]
        column = column.astext
    return query.filter(_dict_key_to_filter(column, key, value))
