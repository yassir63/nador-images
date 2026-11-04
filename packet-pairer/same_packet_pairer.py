from tunnel_identity import load_tunnel_map, metadata_for_event
from flask import Flask, Response
from prometheus_client import Counter, Gauge, Histogram, generate_latest
import argparse
import json
import os
import socket
import threading
import time


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

LABEL_NAMES = [
    "gnb_id",
    "teid",
    "slice",
    "mode",
    "direction",
    "proto",
    "ue_id",
    "imsi",
    "ue_ip",
    "ran_ue_id",
    "teid_direction",
]

PAIR_TTL_NS = int(os.getenv("PACKET_PAIRING_TTL_NS", "10000000000"))
MAX_PENDING_PER_ROLE = int(os.getenv("PACKET_PAIRING_MAX_PENDING", "256"))
SWEEP_INTERVAL_SECONDS = float(os.getenv("PACKET_PAIRING_SWEEP_INTERVAL_SECONDS", "5"))
pending_samples = {}
pending_lock = threading.Lock()


def parse_histogram_buckets():
    raw = os.getenv("PACKET_PAIRING_HISTOGRAM_BUCKETS_NS", "").strip()
    if not raw:
        return DEFAULT_HISTOGRAM_BUCKETS_NS

    try:
        buckets = sorted({float(value.strip()) for value in raw.split(",") if value.strip()})
    except Exception as exc:
        print(f"[packet-pairer] Could not parse PACKET_PAIRING_HISTOGRAM_BUCKETS_NS={raw!r}: {exc}")
        return DEFAULT_HISTOGRAM_BUCKETS_NS

    return buckets or DEFAULT_HISTOGRAM_BUCKETS_NS


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
    except Exception as exc:
        print(f"[packet-pairer] Could not parse TEID_UE_MAP: {exc}")
        return {}

    if not isinstance(parsed, dict):
        print("[packet-pairer] TEID_UE_MAP is not a JSON object")
        return {}

    return load_tunnel_map(parsed)


def ue_id_from_metadata(metadata):
    for field in ("imsi", "ue_ip", "ran_ue_id"):
        value = metadata.get(field, "unknown")
        if value != "unknown":
            return value
    return "unknown"


TEID_UE_MAP = load_teid_ue_map()

parser = argparse.ArgumentParser(description="Same-packet RTT pairer")
parser.add_argument("--port", type=int, default=9200, help="Prometheus HTTP port")
parser.add_argument("--metrics-path", type=str, default="/metrics", help="Prometheus HTTP path")
parser.add_argument("--udp-port", type=int, default=9201, help="UDP port for RTT samples")
args = parser.parse_args()

app = Flask(__name__)

same_packet_upf_rtt_ns = Gauge(
    "gtp_same_packet_upf_rtt_ns",
    "Last-seen UPF RTT for packet samples paired with the same packet at gNB",
    LABEL_NAMES,
)

same_packet_gnb_rtt_ns = Gauge(
    "gtp_same_packet_gnb_rtt_ns",
    "Last-seen gNB RTT for packet samples paired with the same packet at UPF",
    LABEL_NAMES,
)

same_packet_rtt_gap_ns = Gauge(
    "gtp_same_packet_rtt_gap_ns",
    "Last-seen direction-aware RTT gap for the same packet: downlink uses UPF RTT minus gNB RTT, uplink uses gNB RTT minus UPF RTT",
    LABEL_NAMES,
)

same_packet_pairs_total = Counter(
    "gtp_same_packet_pairs_total",
    "Total number of successfully paired same-packet RTT samples",
    LABEL_NAMES,
)

same_packet_upf_rtt_observed_ns = Histogram(
    "gtp_same_packet_upf_rtt_observed_ns",
    "Distribution of paired UPF RTT samples",
    LABEL_NAMES,
    buckets=parse_histogram_buckets(),
)

same_packet_gnb_rtt_observed_ns = Histogram(
    "gtp_same_packet_gnb_rtt_observed_ns",
    "Distribution of paired gNB RTT samples",
    LABEL_NAMES,
    buckets=parse_histogram_buckets(),
)

same_packet_rtt_gap_observed_ns = Histogram(
    "gtp_same_packet_rtt_gap_observed_ns",
    "Distribution of paired direction-aware RTT gaps: downlink uses UPF RTT minus gNB RTT, uplink uses gNB RTT minus UPF RTT",
    LABEL_NAMES,
    buckets=parse_histogram_buckets(),
)

same_packet_pair_rejections_total = Counter(
    "gtp_same_packet_pair_rejections_total",
    "Total number of dropped or invalid same-packet RTT samples",
    ["reason", "mode", "direction"],
)

same_packet_pending_keys = Gauge(
    "gtp_same_packet_pending_keys",
    "Current number of same-packet fingerprint keys kept in memory",
)

same_packet_pending_samples_total = Gauge(
    "gtp_same_packet_pending_samples_total",
    "Current number of pending same-packet samples kept in memory across all roles",
)


def fingerprint_key(evt):
    return (
        label_value(evt.get("mode")),
        label_value(evt.get("logical_direction")),
        label_value(evt.get("proto")),
        normalize_teid(evt.get("teid")),
        label_value(evt.get("outer_dst_ip")),
        label_value(evt.get("src_ip")),
        label_value(evt.get("dst_ip")),
        int(evt.get("src_port", 0)),
        int(evt.get("dst_port", 0)),
        int(evt.get("seq", 0)),
        int(evt.get("payload_len", 0)),
        int(evt.get("tcp_flags", 0)),
    )


def expire_old(entries, now_ns):
    entries[:] = [
        entry for entry in entries
        if now_ns >= entry["received_ns"] and now_ns - entry["received_ns"] <= PAIR_TTL_NS
    ]


def state_is_empty(state):
    return not state["gnb"] and not state["upf"]


def prune_state_if_empty(key, state):
    if state_is_empty(state):
        pending_samples.pop(key, None)
        return True
    return False


def update_pending_metrics():
    same_packet_pending_keys.set(len(pending_samples))
    total_pending = 0
    for state in pending_samples.values():
        total_pending += len(state["gnb"]) + len(state["upf"])
    same_packet_pending_samples_total.set(total_pending)


def sweep_pending_samples():
    while True:
        time.sleep(SWEEP_INTERVAL_SECONDS)
        now_ns = time.monotonic_ns()
        with pending_lock:
            for key, state in list(pending_samples.items()):
                expire_old(state["gnb"], now_ns)
                expire_old(state["upf"], now_ns)
                prune_state_if_empty(key, state)
            update_pending_metrics()


def labels_for_pair(evt):
    teid = normalize_teid(evt.get("teid"))
    ue_metadata = metadata_for_event(TEID_UE_MAP, evt)
    return {
        "gnb_id": ue_metadata.get("gnb_id", "unknown"),
        "teid": teid,
        "slice": label_value(ue_metadata.get("slice_id") or evt.get("slice", "0")),
        "mode": label_value(evt.get("mode", "unknown")),
        "direction": label_value(evt.get("logical_direction", "unknown")),
        "proto": label_value(evt.get("proto", "unknown")),
        "ue_id": ue_id_from_metadata(ue_metadata),
        "imsi": ue_metadata.get("imsi", "unknown"),
        "ue_ip": ue_metadata.get("ue_ip", "unknown"),
        "ran_ue_id": ue_metadata.get("ran_ue_id", "unknown"),
        "teid_direction": ue_metadata.get("teid_direction", "unknown"),
    }


def compute_gap_ns(direction, upf_rtt_ns, gnb_rtt_ns):
    if direction == "downlink":
        return upf_rtt_ns - gnb_rtt_ns
    if direction == "uplink":
        return gnb_rtt_ns - upf_rtt_ns
    return None


def observe_pair(upf_evt, gnb_evt):
    labels = labels_for_pair(upf_evt)
    upf_rtt_ns = int(upf_evt["local_rtt_ns"])
    gnb_rtt_ns = int(gnb_evt["local_rtt_ns"])
    gap_ns = compute_gap_ns(labels["direction"], upf_rtt_ns, gnb_rtt_ns)

    if gap_ns is None:
        same_packet_pair_rejections_total.labels(
            reason="direction",
            mode=labels["mode"],
            direction=labels["direction"],
        ).inc()
        return

    if gap_ns < 0:
        same_packet_pair_rejections_total.labels(
            reason="negative_gap",
            mode=labels["mode"],
            direction=labels["direction"],
        ).inc()
        return

    same_packet_upf_rtt_ns.labels(**labels).set(upf_rtt_ns)
    same_packet_gnb_rtt_ns.labels(**labels).set(gnb_rtt_ns)
    same_packet_rtt_gap_ns.labels(**labels).set(gap_ns)
    same_packet_pairs_total.labels(**labels).inc()
    same_packet_upf_rtt_observed_ns.labels(**labels).observe(upf_rtt_ns)
    same_packet_gnb_rtt_observed_ns.labels(**labels).observe(gnb_rtt_ns)
    same_packet_rtt_gap_observed_ns.labels(**labels).observe(gap_ns)


def process_packet_rtt_sample(evt):
    role = label_value(evt.get("observer_role"))
    mode = label_value(evt.get("mode"))
    direction = label_value(evt.get("logical_direction"))

    if role not in ("gnb", "upf"):
        same_packet_pair_rejections_total.labels(reason="role", mode=mode, direction=direction).inc()
        return

    try:
        local_rtt_ns = int(evt["local_rtt_ns"])
    except Exception:
        same_packet_pair_rejections_total.labels(reason="rtt", mode=mode, direction=direction).inc()
        return

    if local_rtt_ns < 0:
        same_packet_pair_rejections_total.labels(reason="negative_rtt", mode=mode, direction=direction).inc()
        return

    key = fingerprint_key(evt)
    with pending_lock:
        state = pending_samples.setdefault(key, {"gnb": [], "upf": []})
        now_ns = time.monotonic_ns()
        expire_old(state["gnb"], now_ns)
        expire_old(state["upf"], now_ns)

        opposite_role = "upf" if role == "gnb" else "gnb"
        opposite_bucket = state[opposite_role]
        if opposite_bucket:
            peer_evt = opposite_bucket.pop(0)["event"]
            prune_state_if_empty(key, state)
            if role == "upf":
                observe_pair(evt, peer_evt)
            else:
                observe_pair(peer_evt, evt)
            return

        own_bucket = state[role]
        own_bucket.append({
            "received_ns": now_ns,
            "event": evt,
        })
        if len(own_bucket) > MAX_PENDING_PER_ROLE:
            own_bucket.pop(0)
            same_packet_pair_rejections_total.labels(
                reason="pending_overflow",
                mode=mode,
                direction=direction,
            ).inc()


def listen_for_packet_rtt_samples():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.udp_port))
    print(f"[packet-pairer] UDP RTT sample listener on :{args.udp_port}")

    while True:
        data, _ = sock.recvfrom(65535)
        try:
            evt = json.loads(data.decode())
        except Exception:
            continue
        if evt.get("event_type") != "packet_rtt_sample":
            continue
        process_packet_rtt_sample(evt)


@app.route(args.metrics_path)
def metrics():
    return Response(generate_latest(), mimetype="text/plain")


if __name__ == "__main__":
    threading.Thread(target=listen_for_packet_rtt_samples, daemon=True).start()
    threading.Thread(target=sweep_pending_samples, daemon=True).start()
    print(
        f"[packet-pairer] Prometheus HTTP server on :{args.port}{args.metrics_path} "
        f"(ttl_ns={PAIR_TTL_NS}, max_pending_per_role={MAX_PENDING_PER_ROLE}, "
        f"sweep_interval_s={SWEEP_INTERVAL_SECONDS})"
    )
    app.run(host="0.0.0.0", port=args.port)
