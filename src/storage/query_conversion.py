from typing import List, Optional, Union

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


def build_query_from_dict(query_dict: dict, query: Optional[Select] = None) -> Select:  # pylint: disable=too-complex
    '''
    Builds an ``sqlalchemy.orm.Query`` object from a query in dict form.
    '''
    if query is None:
        query = select(FileObjectEntry)

    if '_id' in query_dict:
        # FixMe?: backwards compatible for binary search
        query_dict['uid'] = query_dict.pop('_id')

    analysis_keys = [key for key in query_dict if key.startswith('processed_analysis')]
    if analysis_keys:
        query = _add_analysis_filter_to_query(analysis_keys, query, query_dict)

    firmware_keys = [key for key in query_dict if not key == 'uid' and hasattr(FirmwareEntry, key)]
    if firmware_keys:
        query = query.join(FirmwareEntry, FirmwareEntry.uid == FileObjectEntry.uid)
        query = _add_filters_for_attribute_list(firmware_keys, FirmwareEntry, query, query_dict)

    file_object_keys = [key for key in query_dict if hasattr(FileObjectEntry, key)]
    if file_object_keys:
        query = _add_filters_for_attribute_list(file_object_keys, FileObjectEntry, query, query_dict)

    return query


def _add_filters_for_attribute_list(attribute_list: List[str], table, query: Select, query_dict: dict) -> Select:
    for key in attribute_list:
        column = _get_column(key, table)
        query = query.filter(_dict_key_to_filter(column, query_dict, key))
    return query


def _dict_key_to_filter(column, query_dict: dict, key: str):  # pylint: disable=too-complex,too-many-return-statements
    if not isinstance(query_dict[key], dict):
        return column == query_dict[key]
    if '$exists' in query_dict[key]:
        return column.has_key(key.split('.')[-1])
    if '$regex' in query_dict[key]:
        return column.op('~')(query_dict[key]['$regex'])
    if '$in' in query_dict[key]:  # filter by list
        return column.in_(query_dict[key]['$in'])
    if '$lt' in query_dict[key]:  # less than
        return column < query_dict[key]['$lt']
    if '$gt' in query_dict[key]:  # greater than
        return column > query_dict[key]['$gt']
    if '$contains' in query_dict[key]:  # array contains value
        return column.contains(query_dict[key]['$contains'])
    raise QueryConversionException(f'Search options currently unsupported: {query_dict[key]}')


def _get_column(key: str, table: Union[FirmwareEntry, FileObjectEntry, AnalysisEntry]):
    column = getattr(table, key)
    if key == 'release_date':  # special case: Date column -> convert to string
        return func.to_char(column, 'YYYY-MM-DD')
    return column


def _add_analysis_filter_to_query(analysis_keys: List[str], query: Select, query_dict: dict) -> Select:
    query = query.join(AnalysisEntry, AnalysisEntry.uid == FileObjectEntry.uid)
    for key in analysis_keys:  # type: str
        _, plugin, subkey = key.split('.', maxsplit=2)
        query = query.filter(AnalysisEntry.plugin == plugin)
        if hasattr(AnalysisEntry, subkey):
            if subkey == 'summary':  # special case: array field
                query = _add_summary_filter(query, key, query_dict)
            else:
                query = query.filter(getattr(AnalysisEntry, subkey) == query_dict[key])
        else:  # no metadata field, actual analysis result key in `AnalysisEntry.result` (JSON)
            query = _add_json_filter(query, key, query_dict, subkey)
    return query


def _add_summary_filter(query, key, query_dict):
    if isinstance(query_dict[key], list):  # array can be queried with list or single value
        query = query.filter(AnalysisEntry.summary.contains(query_dict[key]))
    elif isinstance(query_dict[key], dict):
        if '$regex' in query_dict[key]:  # array + "$regex" needs a trick: convert array to string
            column = func.array_to_string(AnalysisEntry.summary, ',')
            query = query.filter(_dict_key_to_filter(column, query_dict, key))
        else:
            raise QueryConversionException(f'Unsupported search option for ARRAY field: {query_dict[key]}')
    else:  # value
        query = query.filter(AnalysisEntry.summary.contains([query_dict[key]]))
    return query


def _add_json_filter(query, key, query_dict, subkey):
    column = AnalysisEntry.result
    if '$exists' in query_dict[key]:
        # "$exists" (aka key exists in json document) is a special case because
        # we need to query the element one level above the actual key
        for nested_key in subkey.split('.')[:-1]:
            column = column[nested_key]
    else:
        for nested_key in subkey.split('.'):
            column = column[nested_key]
        column = column.astext
    return query.filter(_dict_key_to_filter(column, query_dict, key))
