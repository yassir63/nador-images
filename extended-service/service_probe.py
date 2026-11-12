"""Report availability, finite values and event freshness for Prometheus queries."""

import json
import math
import time
from pathlib import Path

import requests
from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import GaugeMetricFamily


def assess(rows, kind, now, max_age):
    """Return nonempty, finite and event-fresh states without inventing zeros."""
    values = [float(row["value"][1]) for row in rows]
    finite = bool(values) and all(math.isfinite(v) for v in values)
    fresh = finite and all(0 <= now - v <= max_age for v in values) if kind == "event_timestamp" else None
    return len(values), finite, fresh


class ServiceCollector:
    def __init__(self, config):
        self.config = config

    def collect(self):
        config = self.config
        if not config["quality"]:
            return
        query_ok = GaugeMetricFamily("nador_quality_query_success", "Prometheus query succeeded; not signal validity", labels=["signal"])
        sample_count = GaugeMetricFamily("nador_quality_series", "Series returned by the instant query", labels=["signal"])
        finite = GaugeMetricFamily("nador_quality_finite", "Nonempty response and all values finite", labels=["signal"])
        fresh = GaugeMetricFamily("nador_quality_event_fresh", "All returned event timestamps within the configured bound", labels=["signal"])
        for spec in config["quality_queries"]:
            try:
                response = requests.get(config["prometheus_url"] + "/api/v1/query",
                                        params={"query": spec["query"]}, timeout=config["timeout_seconds"])
                response.raise_for_status()
                payload = response.json()
                if payload.get("status") != "success" or payload["data"]["resultType"] != "vector":
                    raise ValueError("Quality query must return an instant vector")
                count, valid, timely = assess(payload["data"]["result"], spec["kind"], time.time(), spec["max_age_seconds"])
                query_ok.add_metric([spec["name"]], 1)
                sample_count.add_metric([spec["name"]], count)
                finite.add_metric([spec["name"]], int(valid))
                if timely is not None:
                    fresh.add_metric([spec["name"]], int(timely))
            except (requests.RequestException, KeyError, ValueError, TypeError):
                query_ok.add_metric([spec["name"]], 0)
        yield query_ok
        yield sample_count
        yield finite
        yield fresh


if __name__ == "__main__":
    config = json.loads(Path("/etc/nador-extended/config.json").read_text())
    kind_file = Path("/etc/nador-probe-kind")
    if kind_file.exists() and config.get("probe_kind") != kind_file.read_text().strip():
        raise ValueError("Probe image does not match its configured purpose")
    from runtime import CachedCollector
    REGISTRY.register(CachedCollector(ServiceCollector(config), config["interval_seconds"]))
    start_http_server(9501)
    while True:
        time.sleep(60)
