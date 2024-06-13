from __future__ import annotations

import logging

from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport, log
from graphql import GraphQLSyntaxError

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


def search_gql(query_str: str) -> list[str]:
    query = gql(query_str)
    response = client.execute(query)
    result = []
    for value_list in response.values():
        for dict_ in value_list:
            if uid := dict_.get('uid', dict_.get('file_uid')):
                result.append(uid)
    return result


def validate_gql(query_str: str) -> tuple[bool, str]:
    try:
        gql(query_str)
        return True, ''
    except GraphQLSyntaxError as error:
        return False, str(error)
