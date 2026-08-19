from __future__ import annotations

import json


def test_status_stream_headers_and_heartbeat(test_client):
    """The endpoint returns an event stream with proxy buffers disabled, and the
    FakeSSEQueue emits an immediate heartbeat so the stream is readable without
    any redis."""
    response = test_client.get('/status-stream', buffered=False)
    assert response.status_code == 200
    assert response.mimetype == 'text/event-stream'
    assert response.headers.get('X-Accel-Buffering') == 'no'

    line = ''
    for chunk in response.iter_encoded():
        decoded = chunk.decode()
        if decoded.startswith('data:'):
            line = decoded
            break

    assert json.loads(line.removeprefix('data: ')) == {'type': 'heartbeat'}

    response.close()
