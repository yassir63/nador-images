"""Prometheus quality states."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from service_probe import ServiceCollector, assess


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


def test_quality_collector_does_not_require_active_check_configuration():
    collector = ServiceCollector({"quality": True, "quality_queries": []})
    assert {metric.name for metric in collector.collect()} == {
        "nador_quality_query_success", "nador_quality_series",
        "nador_quality_finite", "nador_quality_event_fresh",
    }
