"""Node-scoped experimental diagnostics, external to the 5G binaries."""

import json
import logging
import os
import subprocess
import time
from collections import defaultdict
from pathlib import Path

from prometheus_client import start_http_server
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

PROC = Path(os.environ.get("HOST_PROC", "/host/proc"))
LOG = logging.getLogger("nador-node-diagnostics")


def run(argv):
    """Never invoke a shell; bound every short-lived diagnostic command."""
    return subprocess.check_output(argv, text=True, timeout=3, stderr=subprocess.DEVNULL)

def collect_qdisc_metrics(records, identity, backlog, drops):
    for record in records:
        labels = identity + [record.get("dev", "unknown"), record.get("handle", "unknown")]
        value = record.get("backlog")
        if type(value) is int and value >= 0:
            backlog.add_metric(labels, value)
        value = record.get("drops")
        if type(value) is int and value >= 0:
            drops.add_metric(labels, value)


def pod_processes(proc, uids):
    """Associate tasks with Kubernetes pod UIDs in v1 or v2 cgroup paths."""
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cgroups = (entry / "cgroup").read_text().replace("_", "-")
            uid = next((uid for uid in uids if "pod" + uid in cgroups), None)
            if uid:
                yield uid, entry
        except (OSError, ProcessLookupError):
            continue


def sched_snapshot(process):
    """Sum all live thread counters. These are snapshots, not monotonic pod totals."""
    runtime = wait = slices = threads = 0
    for task in (process / "task").iterdir():
        try:
            fields = (task / "schedstat").read_text().split()
            runtime += int(fields[0])
            wait += int(fields[1])
            slices += int(fields[2])
            threads += 1
        except (OSError, ValueError, IndexError):
            continue
    return runtime / 1e9, wait / 1e9, slices, threads


class DropReasons:
    """Node-only skb free reasons: never attribute softirq current PID to an NF."""

    def __init__(self):
        self.bpf = None
        try:
            from bcc import BPF
            source = """
            BPF_HASH(reasons, u32, u64, 512);
            TRACEPOINT_PROBE(skb, kfree_skb) {
                u32 key = args->reason;
                if (key > 511) key = 511;
                reasons.atomic_increment(key);
                return 0;
            }
            """
            self.bpf = BPF(text=source)
        except Exception:
            LOG.exception("Drop reason tracepoint unavailable; do not interpret as zero drops")

    def values(self):
        return [] if self.bpf is None else [(int(k.value), int(v.value)) for k, v in self.bpf["reasons"].items()]


class NodeCollector:
    """Refresh discovery before collecting each node-local pod."""

    def __init__(self, config):
        self.config = config
        self.node = os.environ["NODE_NAME"]
        from nador_kernel import KernelSources
        self.kernel = KernelSources(config)
        self.drops = DropReasons() if self.kernel.use_legacy_drop_reasons else None
        self.tcp_flows = None
        if config.get("tcp_flows"):
            from packet_observer import PortableTcpFlows
            self.tcp_flows = PortableTcpFlows(config)
        self.capture = None
        if config["split_signaling"]:
            from split_observer import SplitCapture
            self.capture = SplitCapture(config["capture_limit"])

    def pods(self):
        import requests
        base = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        response = requests.get(
            "https://kubernetes.default.svc/api/v1/pods",
            params={"fieldSelector": "spec.nodeName=" + self.node},
            headers={"Authorization": "Bearer " + (base / "token").read_text().strip()},
            verify=str(base / "ca.crt"), timeout=3,
        )
        response.raise_for_status()
        targets = self.config["targets"]
        result = {}
        for pod in response.json()["items"]:
            meta = pod["metadata"]
            for target in targets:
                if meta["namespace"] == target["namespace"] and all(
                    meta.get("labels", {}).get(k) == v for k, v in target["selector"].items()
                ):
                    result[meta["uid"]] = (meta["namespace"], meta["name"], target["component"])
                    break
        return result

    def collect(self):
        labels = ["node", "namespace", "pod", "component"]
        success = GaugeMetricFamily("nador_extended_collection_success", "Successful collection, not absence of faults", labels=["node", "collector"])
        try:
            pods = self.pods()
            processes = list(pod_processes(PROC, pods))
            success.add_metric([self.node, "pod_discovery"], 1)
        except Exception:
            LOG.exception("Pod discovery failed")
            success.add_metric([self.node, "pod_discovery"], 0)
            yield success
            return
        if self.config["scheduler_wait"]:
            available = GaugeMetricFamily("nador_scheduler_accounting_enabled", "Kernel sched_schedstats enabled; absent is unknown", labels=["node"])
            try:
                available.add_metric([self.node], int((PROC / "sys/kernel/sched_schedstats").read_text().strip()))
            except OSError:
                pass
            yield available
            fields = {
                key: GaugeMetricFamily("nador_nf_" + key, description, labels=labels)
                for key, description in {
                    "runtime_seconds_snapshot": "Runtime summed over currently live threads",
                    "runqueue_wait_seconds_snapshot": "Runnable wait over currently live threads; can decrease on exit",
                    "threads_observed": "Live threads with readable schedstat",
                    "scheduler_read_coverage": "Fraction of discovered processes successfully read",
                }.items()
            }
            sums = defaultdict(lambda: [0, 0, 0, 0])
            expected = defaultdict(int)
            readable = defaultdict(int)
            for uid, process in processes:
                expected[uid] += 1
                try:
                    values = sched_snapshot(process)
                    if values[3]:
                        readable[uid] += 1
                    sums[uid] = [a + b for a, b in zip(sums[uid], values)]
                except OSError:
                    continue
            for uid in pods:
                identity = [self.node, *pods[uid]]
                values = sums[uid]
                if readable[uid]:
                    for key, value in zip(list(fields)[:3], (values[0], values[1], values[3])):
                        fields[key].add_metric(identity, value)
                fields["scheduler_read_coverage"].add_metric(identity, readable[uid] / expected[uid] if expected[uid] else 0)
            yield from fields.values()
        if self.drops:
            success.add_metric([self.node, "kernel_drop_reasons"], int(self.drops.bpf is not None))
            family = GaugeMetricFamily("nador_kernel_skb_free_reason_count", "Cumulative node tracepoint observations since probe start, numeric kernel-local codes; not all packet loss", labels=["node", "reason_code"])
            for reason, count in self.drops.values():
                family.add_metric([self.node, str(reason)], count)
            yield family
        q = GaugeMetricFamily("nador_qdisc_backlog_bytes", "Software qdisc backlog, not hardware queue occupancy", labels=labels + ["interface", "handle"])
        q_drops = CounterMetricFamily("nador_qdisc_dropped_packets", "Software qdisc drops since qdisc creation; not per-UE or end-to-end loss", labels=labels + ["interface", "handle"])
        tcp = GaugeMetricFamily("nador_tcp_namespace_counter", "Cumulative TCP netns counters, not GTP-U tunnel RTT", labels=labels + ["counter"])
        seen = set()
        active = {}
        tcp_targets = {}
        for uid, process in processes:
            if uid in seen:
                continue
            seen.add(uid)
            identity = [self.node, *pods[uid]]
            target = next(t for t in self.config["targets"] if (t["namespace"], t["component"]) ==
                          (pods[uid][0], pods[uid][2]))
            if target["category"] == "ran":
                active[uid] = (process.name, identity)
            if self.tcp_flows:
                tcp_targets[uid] = (process.name, identity)
            if self.config["network_queues"]:
                try:
                    records = json.loads(run(["nsenter", "-t", process.name, "-n", "tc", "-s", "-j", "qdisc", "show"]))
                    collect_qdisc_metrics(records, identity, q, q_drops)
                    success.add_metric([self.node, "qdisc:" + pods[uid][2]], 1)
                except Exception:
                    success.add_metric([self.node, "qdisc:" + pods[uid][2]], 0)
            if self.config["socket_counters"]:
                try:
                    lines = (process / "net/snmp").read_text().splitlines()
                    for i in range(len(lines) - 1):
                        if lines[i].startswith("Tcp:") and lines[i+1].startswith("Tcp:"):
                            values = dict(zip(lines[i].split()[1:], lines[i+1].split()[1:]))
                            for key in ("RetransSegs", "OutRsts", "AttemptFails", "EstabResets"):
                                tcp.add_metric(identity + [key], float(values[key]))
                            break
                    success.add_metric([self.node, "tcp:" + pods[uid][2]], 1)
                except (OSError, ValueError, KeyError):
                    success.add_metric([self.node, "tcp:" + pods[uid][2]], 0)
        if self.config["network_queues"]:
            yield q
            yield q_drops
        if self.config["socket_counters"]:
            yield tcp
        if self.capture:
            self.capture.reconcile(active)
            yield from self.capture.collect()
        if self.config.get("off_cpu") or self.config.get("attributed_drops"):
            from kernel_metrics import kernel_metrics
            self.kernel.reconcile(processes, pods, PROC, self.node)
            yield from kernel_metrics(self.kernel.snapshot(), self.node)
        if self.tcp_flows:
            self.tcp_flows.reconcile(tcp_targets)
            yield from self.tcp_flows.collect()
        yield success


def main():
    from prometheus_client import REGISTRY
    logging.basicConfig(level=logging.INFO)
    config = json.loads(Path("/etc/nador-extended/config.json").read_text())
    kind_file = Path("/etc/nador-probe-kind")
    if kind_file.exists() and config.get("probe_kind") != kind_file.read_text().strip():
        raise ValueError("Probe image does not match its configured purpose")
    from runtime import CachedCollector
    REGISTRY.register(CachedCollector(NodeCollector(config), config["interval_seconds"]))
    start_http_server(9500)
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
