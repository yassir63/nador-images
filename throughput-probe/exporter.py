"""Export mapped N3 tunnel counters; never infer identity from TEID alone."""

import json
import os
import signal
import subprocess
import threading

from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import CounterMetricFamily
from tunnel_identity import metadata_for_event

LABELS = (
    "imsi", "ue_ip", "slice", "gnb_id", "teid", "direction", "outer_dst_ip",
    "session_key", "upf_seid", "smf_seid", "upf_pfcp_ip",
    "probe_role", "probe_pod", "probe_node", "probe_target",
)


# Resolve source counters using the controller's endpoint-scoped session map.
def sample_labels(mapping, sample, environ):
    metadata = metadata_for_event(mapping, sample)
    if not metadata or not metadata.get("imsi") or metadata.get("teid_direction") not in {"ul", "dl"}:
        return None
    values = {
        **metadata,
        "slice": metadata["slice_id"],
        "direction": {"ul": "uplink", "dl": "downlink"}[metadata["teid_direction"]],
        "teid": f"0x{int(sample['teid']):08x}",
        "outer_dst_ip": sample["outer_dst_ip"],
    }
    for name in ("probe_role", "probe_pod", "probe_node", "probe_target"):
        values[name] = environ.get(name.upper(), "")
    return tuple(str(values.get(name) or "") for name in LABELS)


class TunnelCounters:
    """A scrape snapshot of absolute kernel counters; Prometheus derives rates."""

    def __init__(self):
        self.samples = {}
        self.lock = threading.Lock()

    # Publish one map read, keeping each tunnel's cumulative counts.
    def update(self, labels, sample):
        with self.lock:
            self.samples[labels] = (int(sample["packets"]), int(sample["bytes"]))

    # Emit counters without assuming an exact userspace polling interval.
    def collect(self):
        packets = CounterMetricFamily("gtp_throughput_packets", "Inner IP packets per tunnel, counted once from first fragments", labels=LABELS)
        octets = CounterMetricFamily("gtp_throughput_bytes", "Declared inner IP bytes per tunnel, including fragmented datagrams", labels=LABELS)
        with self.lock:
            snapshot = list(self.samples.items())
        for labels, (packet_count, byte_count) in snapshot:
            packets.add_metric(labels, packet_count)
            octets.add_metric(labels, byte_count)
        yield packets
        yield octets


# Run the TC reader and expose only tunnels having an explicit UE owner.
def main():
    mapping = json.loads(os.environ["TEID_UE_MAP"])
    if not mapping or any("|" not in key for key in mapping):
        raise ValueError("Throughput requires endpoint-scoped TEID mappings")
    collector = TunnelCounters()
    REGISTRY.register(collector)
    start_http_server(int(os.environ.get("EXPORTER_PORT", "9300")))
    process = subprocess.Popen(
        ["./gtp_throughput_user", os.environ["IFACE"],
         os.environ.get("HANDLE", "1000"), os.environ.get("PRIO", "1000"), *mapping],
        stdout=subprocess.PIPE,
        text=True,
    )

    # Forward termination so the native reader detaches its TC filters before exit.
    def stop(signum, _frame):
        process.send_signal(signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for line in process.stdout:
            sample = json.loads(line)
            labels = sample_labels(mapping, sample, os.environ)
            if labels is not None:
                collector.update(labels, sample)
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait()
    if process.returncode:
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
