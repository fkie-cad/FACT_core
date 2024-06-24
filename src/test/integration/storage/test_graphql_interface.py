import pytest

from storage.graphql.hasura.init_hasura import HasuraSetup
from storage.graphql.interface import TABLE_TO_QUERY, GraphQlInterface
from test.common_helper import generate_analysis_entry
from test.integration.storage.helper import create_fw_with_child_fo, insert_test_fw


@pytest.fixture
def _init_hasura(_database_interfaces):
    setup = HasuraSetup(testing=True)
    try:
        setup.init_hasura()
        yield
    finally:
        setup.drop_database()


@pytest.fixture
def graphql_interface():
    TABLE_TO_QUERY.update({f'test_{key}': value.replace(key, f'test_{key}') for key, value in TABLE_TO_QUERY.items()})
    return GraphQlInterface()


@pytest.mark.usefixtures('_init_hasura')
def test_graphql_search(backend_db, graphql_interface):
    fo, fw = create_fw_with_child_fo()
    fw.file_name = 'fw.bin'
    fo.file_name = 'some.file'
    fo.processed_analysis = {'plugin_name': generate_analysis_entry(analysis_result={'foo': 'bar'})}
    backend_db.insert_multiple_objects(fw, fo)

    # insert some unrelated objects to assure non-matching objects are not found
    insert_test_fw(backend_db, 'some_other_fw', vendor='other_vendor')

    # the queries in the DB fact_test are prefixed with "test_" to avoid name conflicts
    result, count = graphql_interface.search_gql({'vendor': {'_eq': fw.vendor}}, 'test_firmware')
    assert count == 1
    assert result == [fw.uid]

    result, count = graphql_interface.search_gql({'vendor': {'_in': [fw.vendor, 'other_vendor']}}, 'test_firmware')
    assert count == 2  # noqa: PLR2004

    result, count = graphql_interface.search_gql(
        {'result': {'_contains': {'foo': 'bar'}}, 'plugin': {'_eq': 'plugin_name'}}, 'test_analysis'
    )
    assert count == 1
    assert result == [fo.uid]

    result, count = graphql_interface.search_gql(
        {
            'is_firmware': {'_eq': True},
            'test_firmwareFilesByFirmware': {'test_file_object': {'file_name': {'_eq': fo.file_name}}},
        },
        'test_file_object',
    )
    assert count == 1
    assert result == [fw.uid]
