"""Rate-bounded health checks from explicitly selected NF network namespaces."""

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

from prometheus_client.core import GaugeMetricFamily


def check(pid, target, timeout):
    request = dict(target=target, allowlist=[target], timeout=timeout)
    try:
        output = subprocess.check_output(
            ["nsenter", "-t", pid, "-n", "python3", "/app/active_checks.py", "--internal"],
            input=json.dumps(request), text=True, timeout=timeout, stderr=subprocess.DEVNULL,
        )
        return json.loads(output)
    except subprocess.TimeoutExpired:
        return {"status": "deadline_exceeded", "capability": "unknown", "success": False}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"status": "worker_failed", "capability": "unavailable", "success": False}


def collect_source_checks(sources, config):
    labels = ["node", "namespace", "pod", "component", "target", "transport"]
    states = GaugeMetricFamily("nador_nf_reachability_state", "Outcome of allowlisted check from a source NF network namespace", labels=labels + ["state", "capability"])
    omitted = GaugeMetricFamily("nador_nf_reachability_checks_omitted", "Source checks omitted by per-target source limit", labels=["target"])
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = []
        for target in config["reachability"]:
            if not target.get("source_component"):
                continue
            matches = [(pid, identity) for pid, identity, category in sources.values()
                       if identity[3] == target["source_component"] and category == target["source_category"]]
            limit = config["capture_limit"]
            omitted.add_metric([target["name"]], max(0, len(matches) - limit))
            for pid, identity in sorted(matches)[:limit]:
                jobs.append((identity + [target["name"], target["transport"]],
                             pool.submit(check, pid, target, config["timeout_seconds"])))
        for identity, job in jobs:
            result = job.result()
            states.add_metric(identity + [result["status"], result["capability"]], 1)
    yield states
    yield omitted
