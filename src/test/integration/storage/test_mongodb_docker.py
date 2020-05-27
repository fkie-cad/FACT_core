# pylint:disable=invalid-name,no-self-use

import logging
from configparser import ConfigParser
from contextlib import suppress

import docker
import pytest
from docker.errors import DockerException, NotFound
from requests import ReadTimeout

from helperFunctions.config import load_config
from storage.mongodb_docker import (
    CONTAINER_IP, FACT_MONGODB_NETWORK, MONGODB_CONTAINER_NAME, container_is_running, create_mongodb_container,
    get_docker_network, get_mongodb_container, start_db_container, stop_and_remove_container
)
from test.common_helper import get_config_for_testing

CLIENT = docker.from_env()


def _get_config() -> ConfigParser:
    config = get_config_for_testing()
    fact_config = load_config('main.cfg')
    config.set('data_storage', 'mongo_storage_directory', fact_config.get('data_storage', 'mongo_storage_directory'))
    config.set('Logging', 'mongoDbLogPath', fact_config.get('Logging', 'mongoDbLogPath'))
    return config


def test_get_mongodb_container():
    _make_sure_container_does_not_exist()

    container = get_mongodb_container(_get_config())  # create new container

    assert container.name == MONGODB_CONTAINER_NAME
    assert container.status == 'created'

    container_2 = get_mongodb_container(_get_config())  # load existing container
    assert container == container_2
    networks = container_2.attrs["NetworkSettings"]["Networks"]
    assert FACT_MONGODB_NETWORK in networks
    assert networks[FACT_MONGODB_NETWORK]['IPAMConfig']['IPv4Address'] == CONTAINER_IP


def _make_sure_container_does_not_exist():
    with suppress(NotFound):
        container = CLIENT.containers.get(MONGODB_CONTAINER_NAME)
        if container_is_running(container):
            container.stop()
            container.wait(timeout=10)
        container.remove()


def test_get_docker_network():
    _make_sure_network_does_not_exist()
    network = get_docker_network(CLIENT)
    attributes = network.attrs
    assert attributes.get('Name') == FACT_MONGODB_NETWORK
    assert 'IPAM' in attributes
    assert attributes.get('IPAM').get('Config') != []


def _make_sure_network_does_not_exist():
    with suppress(NotFound):
        network = CLIENT.networks.get(FACT_MONGODB_NETWORK)
        network.remove()


def test_container_is_running():
    container = get_mongodb_container(_get_config())
    container.stop()
    container.wait(timeout=3)
    assert not container_is_running(container)
    try:
        container.start()
        assert container_is_running(container)
    finally:
        container.stop()
        container.wait(timeout=3)


def test_start_db_container_not_running():
    config = _get_config()
    container = get_mongodb_container(config)
    container.stop()
    container.wait(timeout=3)
    with start_db_container(config):
        assert container_is_running(container)
    with pytest.raises(NotFound):
        container.reload()


def test_start_db_container_already_running():
    config = _get_config()
    container = get_mongodb_container(config)
    container.start()
    assert container_is_running(container)
    with start_db_container(config):
        assert container_is_running(container)
    assert container_is_running(container)
    stop_and_remove_container(container)


def test_stop_and_remove_container():
    class MockContainer:
        called = False

        def stop(self):
            pass

        def remove(self):
            pass

        def wait(self, timeout=0):
            raise ReadTimeout()

        def kill(self):
            self.called = True

    container = MockContainer()
    stop_and_remove_container(container)
    assert container.called


def test_create_mongodb_container(caplog):
    class ClientMock:
        class networks:
            def get(self):
                raise DockerException

    with caplog.at_level(logging.ERROR):
        with pytest.raises(DockerException):
            mock_config = {'data_storage': {'mongo_storage_directory': 'foo'}, 'Logging': {'mongoDbLogPath': 'bar'}}
            create_mongodb_container(mock_config, ClientMock())
        assert 'could not start docker mongodb' in caplog.messages[0]
