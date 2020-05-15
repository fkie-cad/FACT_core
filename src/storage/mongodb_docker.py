import logging
import sys
from time import sleep

import docker
from docker import DockerClient
from docker.errors import DockerException, NotFound
from docker.models.containers import Container
from docker.models.networks import Network
from docker.types import Mount

from helperFunctions.config import get_config_dir

MONGODB_CONTAINER_NAME = 'fact_mongodb'
FACT_MONGODB_NETWORK = "fact_mongodb_network"
CONTAINER_IP = '192.168.27.17'
DOCKER_IMAGE = 'mongo:3-xenial'


def get_mongodb_container(config) -> Container:
    client = docker.from_env()
    try:
        mongodb_container = client.containers.get(MONGODB_CONTAINER_NAME)
    except NotFound:
        mongodb_container = create_mongodb_container(config['data_storage']['mongo_storage_directory'], client)
    return mongodb_container


def create_mongodb_container(db_path: str, docker_client: DockerClient) -> Container:
    try:
        mounts = [
            Mount('/config', get_config_dir(), read_only=False, type='bind'),
            Mount('/media/data/fact_wt_mongodb', db_path, read_only=False, type='bind'),
        ]
        network = get_docker_network(docker_client)
        container = docker_client.containers.create(
            DOCKER_IMAGE,
            command='docker-entrypoint.sh --config /config/mongod.conf',
            detach=True,
            name=MONGODB_CONTAINER_NAME,
            mounts=mounts,
        )
        network.connect(MONGODB_CONTAINER_NAME, ipv4_address=CONTAINER_IP)
        return container
    except DockerException as error:
        logging.error('could not start docker mongodb container: {}'.format(error))
        sys.exit(1)


def get_docker_network(docker_client: DockerClient) -> Network:
    try:
        network = docker_client.networks.get(FACT_MONGODB_NETWORK)
    except NotFound:
        network = create_docker_network(docker_client)
    return network


def create_docker_network(client: DockerClient) -> Network:
    ipam_pool = docker.types.IPAMPool(subnet='192.168.27.0/24', gateway='192.168.27.1')
    ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
    return client.networks.create(FACT_MONGODB_NETWORK, driver="bridge", ipam=ipam_config)


def wait_until_started(container: Container):
    iteration = 0
    while 'waiting for connections' not in container.logs().decode():
        sleep(0.5)
        iteration += 1
        if iteration >= 10:
            raise TimeoutError('MongoDB did not start correctly')
