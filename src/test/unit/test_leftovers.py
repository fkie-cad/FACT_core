from __future__ import annotations

from types import SimpleNamespace

from test.leftovers import TEST_EXTRACTOR_PORTS, DbClient, find_leftovers, get_application_name

CONNECTED_AT = 1000.0  # when the PostgreSQL connections were opened


class ProcessFake:
    def __init__(self, pid: int, cmdline: list[str], pgid: int, create_time: float = 0.0):
        self.pid = pid
        self.pgid = pgid
        self._cmdline = cmdline
        self._create_time = create_time

    def cmdline(self) -> list[str]:
        return self._cmdline

    def create_time(self) -> float:
        return self._create_time

    def children(self, recursive: bool = False) -> list[ProcessFake]:
        assert recursive
        return [process for process in PROCESSES if str(process.pid).startswith(str(self.pid)) and process != self]


OWN = ProcessFake(100, ['pytest', 'src/test'], pgid=100)
OWN_CHILD = ProcessFake(101, ['pytest', 'src/test'], pgid=100)
# an aborted test run whose main process 299 (the leader of their process group) has ended; 302 has no connections
ABORTED_MAIN_PID = 299
ABORTED = [ProcessFake(pid, ['python', '-m', 'pytest', 'src/test/acceptance'], pgid=299) for pid in (300, 301, 302)]
# another test run that is still running (with the same command line as this one)
RUNNING = ProcessFake(600, ['pytest', 'src/test'], pgid=600)
RUNNING_CHILD = ProcessFake(601, ['pytest', 'src/test'], pgid=600)
# not a test run: neither its child with another command line nor processes in other process groups are killed
OTHER = ProcessFake(50, ['some-tool'], pgid=50)
OTHER_CHILD = ProcessFake(500, ['some-tool', '--worker'], pgid=50)
UNRELATED = ProcessFake(700, ['python', '-m', 'pytest', 'src/test/acceptance'], pgid=700)
# a process that got the PID of an ended test run's main process after that run connected
REUSED_PID = ProcessFake(800, ['bash'], pgid=800, create_time=CONNECTED_AT + 1)
PROCESSES = [OWN, OWN_CHILD, *ABORTED, RUNNING, RUNNING_CHILD, OTHER, OTHER_CHILD, UNRELATED, REUSED_PID]
PROCESSES_BY_ADDRESS = {
    ('127.0.0.1', 40000): OWN,
    ('127.0.0.1', 40001): OWN_CHILD,
    ('127.0.0.1', 40002): ABORTED[0],
    ('127.0.0.1', 40003): ABORTED[1],
    ('127.0.0.1', 40004): OTHER,
    ('127.0.0.1', 40005): RUNNING_CHILD,
}


class ProcessFinderFake:
    def by_address(self, host: str, port: int) -> ProcessFake | None:
        return PROCESSES_BY_ADDRESS.get((host, port))

    def by_pid(self, pid: int) -> ProcessFake | None:
        return next((process for process in PROCESSES if process.pid == pid), None)

    def by_process_group(self, pgid: int) -> list[ProcessFake]:
        return [process for process in PROCESSES if process.pgid == pgid]

    def get_process_group(self, pid: int) -> int | None:
        return process.pgid if (process := self.by_pid(pid)) else None


def _container(short_id: str, *ports: int) -> SimpleNamespace:
    return SimpleNamespace(
        short_id=short_id, ports={'5000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(port)} for port in ports]}
    )


def _redis(port: int, db: int = 13, host: str = '127.0.0.1') -> dict:
    return {'addr': f'{host}:{port}', 'db': str(db)}


def _db_client(test_run: int | None = None, application_name: str = '') -> DbClient:
    name = get_application_name(test_run) if test_run is not None else application_name
    return DbClient(None, None, name, CONNECTED_AT)


def _find(redis_clients=(), db_clients=(), containers=()) -> str | None:
    return find_leftovers(
        redis_clients=list(redis_clients),
        redis_db=13,
        db_clients=list(db_clients),
        extractor_containers=list(containers),
        test_ports=TEST_EXTRACTOR_PORTS,
        own_pids={OWN.pid, OWN_CHILD.pid},
        find_process=ProcessFinderFake(),
    )


def test_nothing_left():
    message = _find(
        redis_clients=[_redis(40000), _redis(40001), _redis(40002, db=0)],  # own run, and another Redis db
        db_clients=[DbClient('127.0.0.1', 40000, '', CONNECTED_AT), _db_client(OWN.pid)],
        containers=[_container('prod', 9900)],  # e.g. a real FACT backend's extractor
    )

    assert message is None


def test_leftovers_are_named_with_a_cleanup_command():
    message = _find(
        redis_clients=[_redis(40002), _redis(40003), _redis(40004), _redis(40005), _redis(5555, host='10.0.0.5')],
        db_clients=[
            _db_client(RUNNING.pid),
            _db_client(ABORTED_MAIN_PID),
            _db_client(999),  # ended, and no process of it is left here
            _db_client(REUSED_PID.pid),  # ended, and its PID now belongs to another process
            _db_client(application_name='psql'),
        ],
        containers=[_container('abc123', 19900), _container('prod', 9900)],
    )

    assert message is not None
    assert 'another test run is active, or leftovers of an aborted one remain' in message
    assert '- processes 300, 301 (python -m pytest src/test/acceptance): Redis test db 13' in message
    assert '- processes 600, 601 (pytest src/test): Redis test db 13, PostgreSQL test database' in message
    assert '- process 50 (some-tool): Redis test db 13' in message
    assert '- unknown process at 10.0.0.5:5555: Redis test db 13' in message
    assert (
        '- processes of the ended test run 299 (3 left: python -m pytest src/test/acceptance): PostgreSQL test database'
        in message
    )
    assert '- connections of the ended test run 999 (no local process found): PostgreSQL test database' in message
    assert '- connections of the ended test run 800 (no local process found): PostgreSQL test database' in message
    assert "- unknown process (Unix socket, application name 'psql'): PostgreSQL test database" in message
    assert '- extractor container abc123 on port 19900' in message
    assert 'prod' not in message
    # the processes found, and those with the same command line in their process group or below them (302 has no
    # connections), but not this run's, not other children (500), other process groups (700), or a reused PID (800)
    assert 'kill 50 300 301 302 600 601; docker rm -f abc123' in message


def test_only_unknown_processes():
    message = _find(redis_clients=[_redis(5555, host='10.0.0.5')])

    assert message is not None
    assert 'no local process found: check for other test runs, e.g. on other hosts' in message
