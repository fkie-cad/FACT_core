"""
Find what would break a test run: another test run, or what an aborted one left behind (backend processes that keep
polling Redis and writing to the test database, extractor containers on the test ports). A killed pytest leaves its
backend processes and extractor containers running; they take the next run's tasks and write into its database.
"""

from __future__ import annotations

import os
from contextlib import suppress
from typing import TYPE_CHECKING, NamedTuple, Protocol, cast

import docker
import psutil
import pytest
import redis
from docker.errors import DockerException
from sqlalchemy import create_engine, text

import config

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

#: the extractor image and the host ports of the extractor containers started by the tests (not FACT's default port
#: 9900, so that tests never take the extractor containers of a FACT installation on the same system)
TEST_EXTRACTOR_IMAGE = 'fkiecad/fact_extractor:latest'
TEST_EXTRACTOR_PORTS = range(19900, 20000)
_APPLICATION_NAME_PREFIX = 'fact-test-'


def get_application_name(pid: int) -> str:
    """
    The PostgreSQL application name of the connections of the test run whose pytest main process is `pid` (set with
    the libpq environment variable ``PGAPPNAME``, which forked processes inherit, see `src/conftest.py`). FACT connects
    to PostgreSQL over a Unix socket, so the application name is the only way to tell whose connection it is.
    """
    return f'{_APPLICATION_NAME_PREFIX}{pid}'


class DbClient(NamedTuple):
    """A connection to the PostgreSQL test database (``host`` and ``port`` are ``None`` for a Unix socket)"""

    host: str | None
    port: int | None
    application_name: str
    #: when the connection was opened (seconds since the epoch)
    backend_start: float


class ProcessInfo(Protocol):
    """The part of :class:`psutil.Process` that is used here"""

    @property
    def pid(self) -> int: ...

    def cmdline(self) -> list[str]: ...

    def create_time(self) -> float: ...

    def children(self, recursive: bool = False) -> Sequence[ProcessInfo]: ...


class ProcessFinder(Protocol):
    def by_address(self, host: str, port: int) -> ProcessInfo | None:
        """:return: the local process that has the connection with this client address (if any)"""
        ...

    def by_pid(self, pid: int) -> ProcessInfo | None:
        """:return: the process with this PID (if it exists)"""
        ...

    def by_process_group(self, pgid: int) -> Sequence[ProcessInfo]:
        """:return: the processes of this process group (forked processes stay in the one of their parent)"""
        ...

    def get_process_group(self, pid: int) -> int | None:
        """:return: the process group of the process with this PID (if it exists)"""
        ...


class Container(Protocol):
    """The part of :class:`docker.models.containers.Container` that is used here"""

    @property
    def short_id(self) -> str: ...

    @property
    def ports(self) -> dict:
        """container port -> host bindings (e.g. ``{'5000/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '19900'}]}``)"""
        ...


class _Report:
    """
    The leftovers found so far and what each of them uses: processes (grouped by command line), ended test runs (by
    the PID of their main process), and clients whose process is unknown (by a description)
    """

    def __init__(self, own_pids: set[int], find_process: ProcessFinder):
        self._own_pids = own_pids
        self._find_process = find_process
        self._processes: dict[tuple[str, ...], dict[int, ProcessInfo]] = {}
        self._ended_runs: dict[int, Sequence[ProcessInfo]] = {}  # the processes left of them
        self._targets: dict[tuple[str, ...] | int | str, list[str]] = {}
        self._unknown_clients = False

    def add_by_address(self, host: str, port: int, target: str) -> None:
        if process := self._find_process.by_address(host, port):
            self._add_process(process, target)
        else:
            self._add_unknown(f'unknown process at {host}:{port}', target)

    def add_db_client(self, db_client: DbClient) -> None:
        target = 'PostgreSQL test database'
        if (main_pid := _parse_application_name(db_client.application_name)) is not None:
            self._add_test_run(main_pid, db_client.backend_start, target)
        elif db_client.host is not None and db_client.port is not None:
            self.add_by_address(db_client.host, db_client.port, target)
        else:
            self._add_unknown(f"unknown process (Unix socket, application name '{db_client.application_name}')", target)

    def _add_test_run(self, main_pid: int, connected_at: float, target: str) -> None:
        if main_pid in self._own_pids:
            return
        main = self._find_process.by_pid(main_pid)
        if main is not None and _get_create_time(main) <= connected_at:
            self._add_process(main, target)
        elif main is None and (processes := self._find_process.by_process_group(main_pid)):
            # the main process has ended: it was the leader of their process group if a shell started pytest
            self._ended_runs[main_pid] = processes
            self._add_target(main_pid, target)
        else:  # no process is left (or not in the main process's group), or the PID now belongs to another process
            self._add_unknown(f'connections of the ended test run {main_pid} (no local process found)', target)

    def _add_process(self, process: ProcessInfo, target: str) -> None:
        if process.pid in self._own_pids:
            return
        cmdline = tuple(_get_cmdline(process))
        self._processes.setdefault(cmdline, {})[process.pid] = process
        self._add_target(cmdline, target)

    def _add_unknown(self, description: str, target: str) -> None:
        self._unknown_clients = True
        self._add_target(description, target)

    def _add_target(self, key: tuple[str, ...] | int | str, target: str) -> None:
        targets = self._targets.setdefault(key, [])
        if target not in targets:
            targets.append(target)

    def get_lines(self) -> list[str]:
        return [f'- {self._describe(key)}: {", ".join(targets)}' for key, targets in self._targets.items()]

    def _describe(self, key: tuple[str, ...] | int | str) -> str:
        if isinstance(key, tuple):
            pids = sorted(self._processes[key])
            return f'{"process" if len(pids) == 1 else "processes"} {", ".join(map(str, pids))} ({" ".join(key)})'
        if isinstance(key, int):
            processes = self._ended_runs[key]
            return (
                f'processes of the ended test run {key} ({len(processes)} left: {" ".join(_get_cmdline(processes[0]))})'
            )
        return key

    def get_cleanup_command(self, containers: dict[str, int]) -> str:
        pids = self._get_cleanup_pids()
        commands = []
        if pids:
            commands.append(f'kill {" ".join(map(str, pids))}')
        if containers:
            commands.append(f'docker rm -f {" ".join(containers)}')
        if self._unknown_clients and not pids:
            commands.append('(no local process found: check for other test runs, e.g. on other hosts)')
        return '; '.join(commands)

    def _get_cleanup_pids(self) -> list[int]:
        """
        :return: the PIDs of the processes left of ended test runs, of the processes found, and of the processes forked
            from them or from their parent (an aborted test run's processes without connections), but not this run's
        """
        pids = {process.pid for processes in self._ended_runs.values() for process in processes}
        for processes in self._processes.values():
            for process in processes.values():
                pids.update(related.pid for related in self._get_forked_relatives(process))
        return sorted(pids - self._own_pids)

    def _get_forked_relatives(self, process: ProcessInfo) -> list[ProcessInfo]:
        """
        :return: `process` and the processes with its command line (forked processes keep it) among its descendants and
            in its process group (a killed parent's children are no descendants anymore, but stay in its group)
        """
        candidates = list(_get_children(process))
        if (pgid := self._find_process.get_process_group(process.pid)) is not None:
            candidates.extend(self._find_process.by_process_group(pgid))
        cmdline = _get_cmdline(process)
        return [process, *(candidate for candidate in candidates if _get_cmdline(candidate) == cmdline)]


def find_leftovers(
    redis_clients: Iterable[dict],
    redis_db: int,
    db_clients: Iterable[DbClient],
    extractor_containers: Iterable[Container],
    test_ports: range,
    own_pids: set[int],
    find_process: ProcessFinder,
) -> str | None:
    """
    :param redis_clients: all clients of the Redis server (as returned by ``CLIENT LIST``)
    :param redis_db: the number of the Redis test db
    :param db_clients: the connections to the PostgreSQL test database (without the one of this query)
    :param extractor_containers: the running containers of the extractor image of the tests
    :param test_ports: the ports of the extractor containers of the tests
    :param own_pids: this test run's processes (their connections are no leftovers)
    :param find_process: finds local processes
    :return: a message naming the leftovers and how to remove them, or ``None`` if there are none
    """
    report = _Report(own_pids, find_process)
    for client in redis_clients:
        if int(client['db']) == redis_db:
            host, _, port = client['addr'].rpartition(':')
            report.add_by_address(host, int(port), f'Redis test db {redis_db}')
    for db_client in db_clients:
        report.add_db_client(db_client)
    containers = {
        container.short_id: port
        for container in extractor_containers
        if (port := _get_test_port(container, test_ports)) is not None
    }
    lines = [
        *report.get_lines(),
        *(f'- extractor container {short_id} on port {port}' for short_id, port in containers.items()),
    ]
    if not lines:
        return None
    return '\n'.join(
        [
            'Cannot run the tests: another test run is active, or leftovers of an aborted one remain (they would take '
            "this run's tasks and write into its database):",
            *lines,
            f'If no other test run is active, remove them: {report.get_cleanup_command(containers)}',
        ]
    )


def _parse_application_name(name: str) -> int | None:
    """:return: the main PID of the test run with this PostgreSQL application name (``None`` if it is none)"""
    pid = name.removeprefix(_APPLICATION_NAME_PREFIX)
    return int(pid) if name.startswith(_APPLICATION_NAME_PREFIX) and pid.isdigit() else None


def _get_cmdline(process: ProcessInfo) -> list[str]:
    try:
        return process.cmdline()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return ['?']


def _get_create_time(process: ProcessInfo) -> float:
    try:
        return process.create_time()
    except psutil.NoSuchProcess:
        return float('inf')


def _get_children(process: ProcessInfo) -> Sequence[ProcessInfo]:
    try:
        return process.children(recursive=True)
    except psutil.NoSuchProcess:
        return []


def _get_test_port(container: Container, test_ports: range) -> int | None:
    for bindings in container.ports.values():
        for binding in bindings or []:
            if int(binding['HostPort']) in test_ports:
                return int(binding['HostPort'])
    return None


def check_for_leftovers() -> None:
    """
    Stop the test session with a message if another test run is active or an aborted one left something behind (see
    :func:`find_leftovers`). Uses the Redis test db and the PostgreSQL test database of ``config.common``.
    """
    message = find_leftovers(
        redis_clients=_get_redis_clients(),
        redis_db=config.common.redis.test_db,
        db_clients=_get_db_clients(),
        extractor_containers=_get_extractor_containers(),
        test_ports=TEST_EXTRACTOR_PORTS,
        own_pids=_get_own_pids(),
        find_process=_LocalProcessFinder(),
    )
    if message is not None:
        pytest.exit(message, returncode=pytest.ExitCode.USAGE_ERROR)


def _get_redis_clients() -> list[dict]:
    redis_config = config.common.redis
    client = redis.Redis(host=redis_config.host, port=redis_config.port, password=redis_config.password)
    try:
        return cast('list[dict]', client.client_list())
    finally:
        client.close()


def _get_db_clients() -> list[DbClient]:
    postgres = config.common.postgres
    engine = create_engine(
        f'postgresql://{postgres.admin_user}:{postgres.admin_pw}@{postgres.server}:{postgres.port}/'
        f'{postgres.test_database}'
    )
    query = text(
        'SELECT host(client_addr), client_port, application_name, extract(epoch FROM backend_start) '
        'FROM pg_stat_activity '
        "WHERE datname = :database AND backend_type = 'client backend' AND pid <> pg_backend_pid()"
    )
    try:
        with engine.connect() as connection:
            rows = connection.execute(query, {'database': postgres.test_database}).all()
    finally:
        engine.dispose()
    # a Unix socket connection has no client address (and port -1)
    return [
        DbClient(host, port if host is not None else None, name, float(started)) for host, port, name, started in rows
    ]


def _get_extractor_containers() -> Sequence[Container]:
    try:
        client = docker.from_env()
        try:
            return client.containers.list(filters={'ancestor': TEST_EXTRACTOR_IMAGE})
        finally:
            client.close()
    except DockerException:  # Docker is not available: tests that need it fail on their own
        return []


def _get_own_pids() -> set[int]:
    own_process = psutil.Process()
    return {own_process.pid, *(child.pid for child in own_process.children(recursive=True))}


class _LocalProcessFinder:
    """Finds local processes (see :class:`ProcessFinder`)"""

    def __init__(self):
        self._pids_by_address: dict[tuple[str, int], int] | None = None

    def by_address(self, host: str, port: int) -> ProcessInfo | None:
        if self._pids_by_address is None:
            self._pids_by_address = {
                (_normalize_host(connection.laddr.ip), connection.laddr.port): connection.pid
                for connection in psutil.net_connections(kind='inet')
                if connection.pid is not None and connection.laddr
            }
        pid = self._pids_by_address.get((_normalize_host(host), port))
        return self.by_pid(pid) if pid is not None else None

    def by_pid(self, pid: int) -> ProcessInfo | None:
        try:
            return psutil.Process(pid)
        except psutil.NoSuchProcess:
            return None

    def by_process_group(self, pgid: int) -> list[ProcessInfo]:
        return self._find(lambda process: os.getpgid(process.pid) == pgid)

    def get_process_group(self, pid: int) -> int | None:
        try:
            return os.getpgid(pid)
        except ProcessLookupError:
            return None

    @staticmethod
    def _find(condition: Callable[[psutil.Process], bool]) -> list[ProcessInfo]:
        processes = []
        for process in psutil.process_iter():
            with suppress(psutil.AccessDenied, psutil.NoSuchProcess, ProcessLookupError):
                if condition(process):
                    processes.append(process)
        return processes


def _normalize_host(host: str) -> str:
    """Redis writes IPv6 addresses in brackets, and an IPv4 client may appear as IPv4-mapped IPv6 address"""
    return host.strip('[]').removeprefix('::ffff:')
