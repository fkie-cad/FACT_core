from http import HTTPStatus

import pytest
import requests


@pytest.mark.parametrize('error', [requests.ConnectionError('refused'), requests.Timeout('timed out')])
def test_graphql_proxy_hasura_unreachable(test_client, monkeypatch, error):
    def _raise(**_):
        raise error

    monkeypatch.setattr('web_interface.components.database_routes.requests.request', _raise)
    response = test_client.post('/graphql', json={'query': '{ firmware { uid } }'})

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert response.json['errors'][0]['message'].startswith("FACT's GraphQL service (Hasura) is not reachable")
