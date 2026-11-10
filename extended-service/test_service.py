"""Quality states and explicitly scoped TCP connectivity checks."""

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from service_probe import assess, connect


def rows(*values):
    return [{"metric": {}, "value": [100, str(value)]} for value in values]


@pytest.mark.parametrize("values,expected", [
    ([], (0, False, False)),
    ([95], (1, True, True)),
    ([1], (1, True, False)),
    ([101], (1, True, False)),
    ([float("nan")], (1, False, False)),
    ([95, 1], (2, True, False)),
])
def test_event_freshness(values, expected):
    assert assess(rows(*values), "event_timestamp", 100, 10) == expected


def test_availability_is_not_event_freshness():
    assert assess(rows(95), "availability", 100, 10) == (1, True, None)


def test_tcp_success():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        ok, duration = connect({"host": "127.0.0.1", "port": server.getsockname()[1]}, .2)
    assert ok == 1 and duration >= 0


def test_tcp_failure():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
    assert connect({"host": "127.0.0.1", "port": port}, .2)[0] == 0
