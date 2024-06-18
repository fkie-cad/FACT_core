from __future__ import annotations

import logging

from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport, log

import config

config.load()
URL = f'http://localhost:{config.frontend.hasura.port}/v1/graphql'
HEADERS = {
    'Content-Type': 'application/json',
    'X-Hasura-Role': 'admin',
    'X-Hasura-Admin-Secret': config.frontend.hasura.admin_secret,
}
transport = AIOHTTPTransport(url=URL, headers=HEADERS)
client = Client(transport=transport)
log.setLevel(logging.WARNING)  # disable noisy gql logs

FO_QUERY = """
query file_object($where: file_object_bool_exp, $limit: Int, $offset: Int) {
  file_object_aggregate(where: $where) {
    aggregate {
      totalCount: count
    }
  }
  file_object(where: $where, limit: $limit, offset: $offset) {
    uid
  }
}
"""
FW_QUERY = """
query firmware($where: firmware_bool_exp, $limit: Int, $offset: Int) {
  firmware_aggregate(where: $where) {
    aggregate {
      totalCount: count
    }
  }
  firmware(where: $where, limit: $limit, offset: $offset, order_by: {vendor: asc}) {
    uid
  }
}
"""
ANALYSIS_QUERY = """
query analysis($where: analysis_bool_exp, $limit: Int, $offset: Int) {
  analysis_aggregate(where: $where, distinct_on: uid) {
    aggregate {
      totalCount: count
    }
  }
  analysis(where: $where, limit: $limit, offset: $offset, distinct_on: uid) {
    uid
  }
}
"""
TABLE_TO_QUERY = {
    'file_object': FO_QUERY,
    'firmware': FW_QUERY,
    'analysis': ANALYSIS_QUERY,
}
# these queries are simplified versions of the ones above that are displayed in the web interface
TEMPLATE_QUERIES = {
    'file_object': (
        'query file_object_query($where: file_object_bool_exp) {\n'
        '    file_object(where: $where) {\n'
        '        uid\n'
        '    }\n'
        '}'
    ),
    'firmware': (
        'query firmware_query($where: file_object_bool_exp) {\n'
        '    firmware(where: $where, order_by: {vendor: asc}) {\n'
        '        uid\n'
        '    }\n'
        '}'
    ),
    'analysis': (
        'query analysis_query($where: file_object_bool_exp) {\n'
        '    analysis(where: $where, distinct_on: uid) {\n'
        '        uid\n'
        '    }\n'
        '}'
    ),
}


class GraphQLSearchError(Exception):
    pass


def search_gql(
    where: dict,
    table: str,
    offset: int | None = None,
    limit: int | None = None,
) -> tuple[list[str], int]:
    """
    Search the database using a GraphQL query.

    :param where: $where part of the query as dict.
    :param table: name of the table we are searching. Must be one of "file_object", "firmware", "analysis".
    :param offset: number of items to skip.
    :param limit: number of items to return.
    :return: Tuple with a list of matching uids and the total number of matches.
    """
    variables = {'where': where}
    if offset is not None:
        variables['offset'] = offset
    if limit is not None:
        variables['limit'] = limit

    if not (query := TABLE_TO_QUERY[table]):
        raise GraphQLSearchError(f'Unknown table {table}')

    response = client.execute(gql(query), variable_values=variables)
    total = response.get(f'{table}_aggregate', {}).get('aggregate', {}).get('totalCount')
    if not total:
        raise GraphQLSearchError('Could not determine total result count')
    return [e['uid'] for e in response.get(table, {})], total
