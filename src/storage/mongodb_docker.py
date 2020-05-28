import logging
from configparser import ConfigParser
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, Dict

import docker
from docker import DockerClient
from docker.errors import DockerException, NotFound
from docker.models.containers import Container
from docker.models.networks import Network
from docker.types import Mount
from requests.exceptions import ReadTimeout

from helperFunctions.config import get_config_dir

DOCKER_COMMAND = 'docker-entrypoint.sh --config /config/mongod.conf --setParameter honorSystemUmask=true'

MONGODB_CONTAINER_NAME = 'fact_mongodb'
FACT_MONGODB_NETWORK = "fact_mongodb_network"
DOCKER_IMAGE = 'mongo:3.6.8-stretch'
LOCALHOST = ['localhost', '127.0.0.1']


@contextmanager
def start_db_container(config: ConfigParser) -> Container:
    mongodb_container = get_mongodb_container(config)
    running = container_is_running(mongodb_container)
    try:
        if not running:
            logging.info('Starting MongoDB container...')
            mongodb_container.start()
        yield mongodb_container
    finally:
        if not running:
            logging.info('Stopping MongoDB container...')
            with suppress(DockerException):
                stop_and_remove_container(mongodb_container)


def stop_and_remove_container(mongodb_container: Container):
    mongodb_container.stop()
    try:
        mongodb_container.wait(timeout=10)
    except ReadTimeout:
        logging.error('Unable to stop MongoDB container -> kill')
        mongodb_container.kill()
    mongodb_container.remove()


def get_mongodb_container(config) -> Container:
    client = docker.from_env()
    try:
        mongodb_container = client.containers.get(MONGODB_CONTAINER_NAME)
    except NotFound:
        mongodb_container = create_mongodb_container(config, client)
    return mongodb_container


def create_mongodb_container(config: ConfigParser, docker_client: DockerClient) -> Container:
    try:
        container_config = _get_container_config(config)
        container = docker_client.containers.create(DOCKER_IMAGE, command=DOCKER_COMMAND, **container_config)
        ip_address = config['data_storage']['mongo_server']
        if ip_address not in LOCALHOST:
            network = get_docker_network(config, docker_client)
            network.connect(MONGODB_CONTAINER_NAME, ipv4_address=ip_address)
        return container
    except DockerException as error:
        logging.error('could not start docker mongodb container: {}'.format(error))
        raise


def _get_container_config(config: ConfigParser) -> Dict[str, Any]:
    db_path, ip_address = config['data_storage']['mongo_storage_directory'], config['data_storage']['mongo_server']
    log_path = Path(config['Logging']['mongoDbLogPath'])
    logging.info('creating mongodb docker container\n\tdatabase path: {}\n\tlog path: {})'.format(db_path, log_path))
    mounts = [
        Mount('/config', get_config_dir(), read_only=False, type='bind'),
        Mount('/media/data/fact_wt_mongodb', db_path, read_only=False, type='bind'),
        Mount('/log', str(log_path), read_only=False, type='bind'),
    ]
    container_config = {
        'detach': True,
        'name': MONGODB_CONTAINER_NAME,
        'mounts': mounts,
        'ports': {'27018/tcp': config['data_storage']['mongo_port']},
    }
    if ip_address in LOCALHOST:
        container_config['network_mode'] = 'host'
    return container_config


def get_docker_network(config: ConfigParser, docker_client: DockerClient) -> Network:
    try:
        network = docker_client.networks.get(FACT_MONGODB_NETWORK)
        if not network_conf_is_correct(network, config):
            raise NotFound
    except NotFound:
        network = create_docker_network(config, docker_client)
    return network


def network_conf_is_correct(network: Network, config: ConfigParser) -> bool:
    try:
        network_config = network.attrs['IPAM']['Config'][0]
        network_subnet, network_gateway = network_config['Subnet'], network_config['Gateway']
        config_subnet, config_gateway = config['data_storage']['mongo_subnet'], config['data_storage']['mongo_gateway']
        return network_subnet == config_subnet and network_gateway == config_gateway
    except (IndexError, KeyError):
        return False


def create_docker_network(config: ConfigParser, client: DockerClient) -> Network:
    subnet, gateway = config['data_storage']['mongo_subnet'], config['data_storage']['mongo_gateway']
    ipam_pool = docker.types.IPAMPool(subnet=subnet, gateway=gateway)
    ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
    return client.networks.create(FACT_MONGODB_NETWORK, driver="bridge", ipam=ipam_config)


def container_is_running(container: Container) -> bool:
    container.reload()
    return container.status == 'running'
