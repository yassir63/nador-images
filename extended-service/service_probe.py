"""Quality and allowlisted TCP checks. No synthetic 3GPP procedure generation."""

import json
import math
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
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


def connect(target, timeout):
    """Check TCP connection establishment only; no claim about SBI semantics."""
    start = time.monotonic()
    if target.get("addresses"):
        from active_checks import run_check
        response = run_check(dict(target=target, allowlist=[target], timeout=timeout))
        return int(response["success"]), time.monotonic() - start
    try:
        # Bound DNS resolution too; socket timeouts alone do not bound getaddrinfo.
        code = "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),float(sys.argv[3])); s.close()"
        subprocess.run([sys.executable, "-c", code, target["host"], str(target["port"]), str(timeout)],
                       check=True, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 1, time.monotonic() - start
    except (OSError, subprocess.SubprocessError):
        return 0, time.monotonic() - start


class ServiceCollector:
    def __init__(self, config):
        self.config = config

    def collect(self):
        config = self.config
        success = GaugeMetricFamily("nador_reachability_success", "TCP connect success from this collector pod, not source NF or 3GPP procedure success", labels=["target"])
        duration = GaugeMetricFamily("nador_reachability_duration_seconds", "TCP connect attempt elapsed time including failed attempts", labels=["target"])
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [(target, pool.submit(connect, target, config["timeout_seconds"]))
                       for target in config["reachability"] if not target.get("source_component")]
            for target, future in futures:
                ok, elapsed = future.result()
                success.add_metric([target["name"]], ok)
                duration.add_metric([target["name"]], elapsed)
        yield success
        yield duration
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
    from runtime import CachedCollector
    REGISTRY.register(CachedCollector(ServiceCollector(config), config["interval_seconds"]))
    start_http_server(9501)
    while True:
        time.sleep(60)
