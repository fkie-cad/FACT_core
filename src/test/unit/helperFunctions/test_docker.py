from unittest.mock import MagicMock

import docker

from helperFunctions.docker import run_docker_container


def test_run_docker_container_removes_anonymous_volumes(monkeypatch):
    container = MagicMock()
    container.wait.return_value = {'StatusCode': 0}
    container.logs.return_value = b''
    client = MagicMock()
    client.containers.run.return_value = container
    monkeypatch.setattr(docker.client, 'from_env', lambda: client)

    run_docker_container('some/image', command='foo')

    # without v=True, docker keeps the anonymous volumes of images that declare a VOLUME
    container.remove.assert_called_once_with(v=True)
