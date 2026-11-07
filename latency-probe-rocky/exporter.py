from tunnel_identity import load_tunnel_map, metadata_for_event
from flask import Flask, Response
from prometheus_client import Counter, Gauge, Histogram, generate_latest
import threading
import json
import socket
import os
import argparse
import statistics
import time

SOCKET_PATH = "/tmp/gtp_latency.sock"
PROBE_ROLE = os.getenv("PROBE_ROLE", "gnb")
PROBE_POD = os.getenv("PROBE_POD", "unknown")
PROBE_NODE = os.getenv("PROBE_NODE", "unknown")
PROBE_TARGET = os.getenv("PROBE_TARGET", "unknown")
latency_cache = {}
latency_median_samples = {}
latency_median_lock = threading.Lock()

LABEL_NAMES = [
    "gnb_id",
    "teid",
    "slice",
    "mode",
    "kind",
    "probe_role",
    "probe_pod",
    "probe_node",
    "probe_target",
    "ue_id",
    "imsi",
    "ue_ip",
    "ran_ue_id",
    "teid_direction",
]

DEBUG_LABEL_NAMES = LABEL_NAMES + [
    "debug_proto",
    "debug_action",
]

LOST_LABEL_NAMES = [
    "probe_role",
    "probe_pod",
    "probe_node",
    "probe_target",
    "stream",
]

TCP_CORR_LABEL_NAMES = [
    "mode",
    "probe_role",
    "probe_pod",
    "probe_node",
    "probe_target",
]

TCP_CORR_EVICT_LABEL_NAMES = TCP_CORR_LABEL_NAMES + [
    "reason",
]

DEFAULT_HISTOGRAM_BUCKETS_NS = [
    50_000,
    100_000,
    250_000,
    500_000,
    750_000,
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    20_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
]


def parse_histogram_buckets():
    raw = os.getenv("LATENCY_HISTOGRAM_BUCKETS_NS", "").strip()
    if not raw:
        return DEFAULT_HISTOGRAM_BUCKETS_NS

    try:
        buckets = sorted({float(value.strip()) for value in raw.split(",") if value.strip()})
    except Exception as e:
        print(f"[exporter] Could not parse LATENCY_HISTOGRAM_BUCKETS_NS={raw!r}: {e}")
        return DEFAULT_HISTOGRAM_BUCKETS_NS

    if not buckets:
        print("[exporter] LATENCY_HISTOGRAM_BUCKETS_NS was empty after parsing; using defaults")
        return DEFAULT_HISTOGRAM_BUCKETS_NS

    return buckets


def normalize_teid(value):
    try:
        return f"0x{int(str(value).strip(), 0):08x}"
    except Exception:
        return str(value or "")


def label_value(value):
    value = str(value or "").strip()
    return value if value else "unknown"


def load_teid_ue_map():
    raw = os.getenv("TEID_UE_MAP", "{}")
    try:
        parsed = json.loads(raw)
    except Exception as e:
        print(f"[exporter] Could not parse TEID_UE_MAP: {e}")
        return {}

    if not isinstance(parsed, dict):
        print("[exporter] TEID_UE_MAP is not a JSON object")
        return {}

    return load_tunnel_map(parsed)


def ue_id_from_metadata(metadata):
    for field in ("imsi", "ue_ip", "ran_ue_id"):
        value = metadata.get(field, "unknown")
        if value != "unknown":
            return value
    return "unknown"


TEID_UE_MAP = load_teid_ue_map()

# Parse command line arguments
parser = argparse.ArgumentParser(description='GTP Latency Exporter')
parser.add_argument('--port', type=int, default=8000, help='Port to expose metrics on')
parser.add_argument('--metrics-path', type=str, default='/metrics', help='Path to expose metrics on')
args = parser.parse_args()

app = Flask(__name__)
latency_ns = Gauge(
    "gtp_teid_latency_ns",
    "Last-seen GTP latency (ns)",
    LABEL_NAMES,
)

latency_events_total = Counter(
    "gtp_teid_latency_events_total",
    "Total number of GTP latency events observed by the exporter",
    LABEL_NAMES,
)

latency_median_1s_ns = Gauge(
    "gtp_teid_latency_median_1s_ns",
    "Exact median GTP latency observed by the exporter over the last 1-second interval (ns)",
    LABEL_NAMES,
)

latency_observed_ns = Histogram(
    "gtp_teid_latency_observed_ns",
    "Distribution of observed GTP latency events (ns)",
    LABEL_NAMES,
    buckets=parse_histogram_buckets(),
)

latency_debug_events_total = Counter(
    "gtp_teid_latency_debug_events_total",
    "Total number of optional latency match debug events observed by the exporter",
    DEBUG_LABEL_NAMES,
)

latency_lost_events_total = Counter(
    "gtp_teid_latency_lost_events_total",
    "Total number of userspace perf-buffer events lost before processing",
    LOST_LABEL_NAMES,
)

tcp_data_observed_total = Counter(
    "gtp_tcp_data_observed_total",
    "Total number of TCP data observations entering the userspace correlator",
    TCP_CORR_LABEL_NAMES,
)

tcp_ack_observed_total = Counter(
    "gtp_tcp_ack_observed_total",
    "Total number of TCP ACK observations entering the userspace correlator",
    TCP_CORR_LABEL_NAMES,
)

tcp_rtt_emitted_total = Counter(
    "gtp_tcp_rtt_emitted_total",
    "Total number of TCP RTT samples emitted by the userspace correlator",
    TCP_CORR_LABEL_NAMES,
)

tcp_pending_evicted_total = Counter(
    "gtp_tcp_pending_evicted_total",
    "Total number of pending TCP samples evicted before a matching ACK arrived",
    TCP_CORR_EVICT_LABEL_NAMES,
)

tcp_ack_no_match_total = Counter(
    "gtp_tcp_ack_no_match_total",
    "Total number of TCP ACK observations that found no pending sample to match",
    TCP_CORR_LABEL_NAMES,
)


def base_labels_for_event(evt):
    teid = normalize_teid(evt["teid"])
    mode = label_value(evt.get("mode", "core"))
    kind = label_value(evt.get("kind", "debug"))
    ue_metadata = metadata_for_event(TEID_UE_MAP, evt)
    imsi = ue_metadata.get("imsi", "unknown")
    ue_ip = ue_metadata.get("ue_ip", "unknown")
    ran_ue_id = ue_metadata.get("ran_ue_id", "unknown")
    teid_direction = ue_metadata.get("teid_direction", "unknown")
    ue_id = ue_id_from_metadata(ue_metadata)

    return {
        "gnb_id": ue_metadata.get("gnb_id", "unknown"),
        "teid": teid,
        "slice": label_value(ue_metadata.get("slice_id") or evt.get("slice", "0")),
        "mode": mode,
        "kind": kind,
        "probe_role": label_value(PROBE_ROLE),
        "probe_pod": label_value(PROBE_POD),
        "probe_node": label_value(PROBE_NODE),
        "probe_target": label_value(PROBE_TARGET),
        "ue_id": ue_id,
        "imsi": imsi,
        "ue_ip": ue_ip,
        "ran_ue_id": ran_ue_id,
        "teid_direction": teid_direction,
    }


def labels_for_event(evt):
    labels = base_labels_for_event(evt)
    labels["kind"] = label_value(evt.get("kind", "unknown"))
    return labels


def normalize_debug_action(action):
    action = label_value(action)

    # The mode is already a separate label, so keep the action itself compact.
    for prefix in ("core_", "ran_"):
        if action.startswith(prefix):
            return action[len(prefix):]

    return action


def observe_latency_event(evt):
    latency_value = int(evt["latency_ns"])
    labels = labels_for_event(evt)
    label_tuple = tuple(labels[name] for name in LABEL_NAMES)
    latency_cache[label_tuple] = latency_value
    with latency_median_lock:
        latency_median_samples.setdefault(label_tuple, []).append(latency_value)
    latency_ns.labels(**labels).set(latency_value)

    latency_events_total.labels(**labels).inc()
    latency_observed_ns.labels(**labels).observe(latency_value)


def observe_debug_event(evt):
    labels = base_labels_for_event(evt)
    labels["debug_proto"] = label_value(evt.get("debug_proto", "unknown"))
    labels["debug_action"] = normalize_debug_action(evt.get("debug_action", "unknown"))
    latency_debug_events_total.labels(**labels).inc()


def observe_lost_event(evt):
    labels = {
        "probe_role": label_value(PROBE_ROLE),
        "probe_pod": label_value(PROBE_POD),
        "probe_node": label_value(PROBE_NODE),
        "probe_target": label_value(PROBE_TARGET),
        "stream": label_value(evt.get("stream", "unknown")),
    }

    latency_lost_events_total.labels(**labels).inc(int(evt.get("lost_count", 0)))


def observe_tcp_corr_stats_event(evt):
    labels = {
        "mode": label_value(evt.get("mode", "unknown")),
        "probe_role": label_value(PROBE_ROLE),
        "probe_pod": label_value(PROBE_POD),
        "probe_node": label_value(PROBE_NODE),
        "probe_target": label_value(PROBE_TARGET),
    }

    data_observed = int(evt.get("data_observed_count", 0))
    ack_observed = int(evt.get("ack_observed_count", 0))
    rtt_emitted = int(evt.get("rtt_emitted_count", 0))
    ack_no_match = int(evt.get("ack_no_match_count", 0))
    evicted_overwrite = int(evt.get("pending_evicted_overwrite_count", 0))
    evicted_ttl = int(evt.get("pending_evicted_ttl_count", 0))
    evicted_flow_reuse = int(evt.get("pending_evicted_flow_reuse_count", 0))

    if data_observed > 0:
        tcp_data_observed_total.labels(**labels).inc(data_observed)
    if ack_observed > 0:
        tcp_ack_observed_total.labels(**labels).inc(ack_observed)
    if rtt_emitted > 0:
        tcp_rtt_emitted_total.labels(**labels).inc(rtt_emitted)
    if ack_no_match > 0:
        tcp_ack_no_match_total.labels(**labels).inc(ack_no_match)

    if evicted_overwrite > 0:
        tcp_pending_evicted_total.labels(**labels, reason="overwrite").inc(evicted_overwrite)
    if evicted_ttl > 0:
        tcp_pending_evicted_total.labels(**labels, reason="ttl").inc(evicted_ttl)
    if evicted_flow_reuse > 0:
        tcp_pending_evicted_total.labels(**labels, reason="flow_reuse").inc(evicted_flow_reuse)


def flush_latency_medians():
    while True:
        now = time.time()
        sleep_seconds = 1.0 - (now % 1.0)
        time.sleep(sleep_seconds if sleep_seconds > 0 else 1.0)

        with latency_median_lock:
            samples_by_label = latency_median_samples.copy()
            latency_median_samples.clear()

        for label_tuple, samples in samples_by_label.items():
            if not samples:
                continue

            labels = dict(zip(LABEL_NAMES, label_tuple))
            latency_median_1s_ns.labels(**labels).set(statistics.median(samples))


def listen_on_socket():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.bind(SOCKET_PATH)
    except OSError:
        os.remove(SOCKET_PATH)
        sock.bind(SOCKET_PATH)
    print(f"[exporter] Listening on {SOCKET_PATH}")
    while True:
        data, _ = sock.recvfrom(1024)
        try:
            evt = json.loads(data.decode("utf-8"))
            event_type = label_value(evt.get("event_type", "latency"))
            if event_type == "latency_debug":
                observe_debug_event(evt)
            elif event_type == "latency_lost":
                observe_lost_event(evt)
            elif event_type == "tcp_corr_stats":
                observe_tcp_corr_stats_event(evt)
            else:
                observe_latency_event(evt)
        except Exception as e:
            print("bad payload:", e)

@app.route("/" + args.metrics_path.lstrip("/"))
def metrics():
    return Response(generate_latest(), mimetype="text/plain")

if __name__ == "__main__":
    threading.Thread(target=listen_on_socket, daemon=True).start()
    threading.Thread(target=flush_latency_medians, daemon=True).start()
    print(f"Deploying Latency Exporter on port {args.port} serving at {args.metrics_path}")

    app.run(host="0.0.0.0", port=args.port)
