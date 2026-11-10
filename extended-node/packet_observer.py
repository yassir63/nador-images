"""Portable, bounded packet evidence. No subscriber joins or inferred packet loss."""

import argparse
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import selectors
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass


class DecodeError(ValueError):
    pass


@dataclass(frozen=True)
class GTPU:
    teid: int
    qfi: object
    sequence: object
    npdu: object
    extensions: tuple
    payload: bytes
    pdu_type: object


def decode_gtpu(data, max_extensions=16):
    """TS 29.281: optional quartet exists if ANY of E/S/PN is set."""
    if len(data) < 8:
        raise DecodeError("gtp_short")
    flags, kind, length, teid = struct.unpack_from("!BBHI", data)
    if flags >> 5 != 1 or not flags & 0x10 or flags & 0x08 or kind != 255:
        raise DecodeError("gtp_not_v1_tpdu")
    end = 8 + length
    if end != len(data):
        raise DecodeError("gtp_length")
    offset, nxt, sequence, npdu = 8, 0, None, None
    if flags & 7:
        if end < 12:
            raise DecodeError("gtp_optional_short")
        sequence = int.from_bytes(data[8:10], "big") if flags & 2 else None
        npdu = data[10] if flags & 1 else None
        nxt = data[11] if flags & 4 else 0
        offset = 12
    extensions, qfi, pdu_type = [], None, None
    while nxt:
        if len(extensions) >= max_extensions:
            raise DecodeError("gtp_extension_limit")
        if offset >= end:
            raise DecodeError("gtp_extension_short")
        size = data[offset] * 4
        if size < 4 or offset + size > end:
            raise DecodeError("gtp_extension_length")
        extensions.append(nxt)
        if nxt == 0x85:
            if extensions.count(0x85) != 1:
                raise DecodeError("gtp_duplicate_psc")
            pdu_type = data[offset + 1] >> 4
            # Only DL/UL PDU SESSION INFORMATION have the supported QFI layout.
            if pdu_type in (0, 1):
                qfi = data[offset + 2] & 0x3f
        nxt = data[offset + size - 1]
        offset += size
    if flags & 4 and not extensions:
        raise DecodeError("gtp_empty_extension_chain")
    return GTPU(teid, qfi, sequence, npdu, tuple(extensions), data[offset:end], pdu_type)


def ip_packet(data):
    """Return complete unfragmented IP, header length, protocol, endpoint bytes.

    IPv6 extension headers/jumbograms are deliberately unsupported. No reassembly.
    """
    if not data:
        raise DecodeError("ip_short")
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            raise DecodeError("ipv4_short")
        header = (data[0] & 15) * 4
        length = int.from_bytes(data[2:4], "big")
        if header < 20 or length < header or length > len(data):
            raise DecodeError("ipv4_length")
        if int.from_bytes(data[6:8], "big") & 0x3fff:
            raise DecodeError("ip_fragment")
        return data[:length], header, data[9], data[12:20]
    if version == 6:
        if len(data) < 40:
            raise DecodeError("ipv6_short")
        length = 40 + int.from_bytes(data[4:6], "big")
        if length == 40 or length > len(data):
            raise DecodeError("ipv6_length")
        if data[6] in (0, 43, 44, 50, 51, 60, 135, 139, 140):
            raise DecodeError("ipv6_extensions_unsupported")
        return data[:length], 40, data[6], data[8:40]
    raise DecodeError("ip_version")


def ethernet_ip(frame):
    if len(frame) < 14:
        raise DecodeError("ethernet_short")
    kind, offset = int.from_bytes(frame[12:14], "big"), 14
    for _ in range(2):
        if kind not in (0x8100, 0x88a8):
            break
        if len(frame) < offset + 4:
            raise DecodeError("vlan_short")
        kind = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if kind not in (0x0800, 0x86dd):
        raise DecodeError("ethernet_not_ip")
    return ip_packet(frame[offset:])


def canonical_ip(data):
    packet, _, _, _ = ip_packet(data)
    if len(packet) != len(data):
        raise DecodeError("inner_ip_trailing")
    canonical = bytearray(packet)
    if packet[0] >> 4 == 4:
        canonical[8] = 0
        canonical[10:12] = b"\0\0"
    else:
        canonical[7] = 0
    return bytes(canonical)


def digest(key, *parts):
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        value = part if isinstance(part, bytes) else str(part).encode()
        mac.update(len(value).to_bytes(4, "big"))
        mac.update(value)
    return mac.hexdigest()


def packet_evidence(frame, key, run_id, source):
    outer, header, protocol, endpoints = ethernet_ip(frame)
    if protocol != 17:
        raise DecodeError("not_gtpu_udp")
    udp = outer[header:]
    if len(udp) < 8:
        raise DecodeError("udp_short")
    sport, dport, length = struct.unpack_from("!HHH", udp)
    if 2152 not in (sport, dport):
        raise DecodeError("not_gtpu_udp")
    if length < 8 or length != len(udp):
        raise DecodeError("udp_length")
    gtp = decode_gtpu(udp[8:])
    inner = canonical_ip(gtp.payload)
    # Directional outer endpoints + TEID scope prevents unrelated-tunnel joins.
    # UDP source port is excluded: it may vary for ECMP without changing tunnel.
    scope = digest(key, "scope-v1", run_id, outer[0] >> 4, endpoints, gtp.teid)
    packet_id = digest(key, "packet-v1", run_id, scope, inner)
    source_id = digest(key, "source-v1", run_id, source)
    return gtp, {"scope_id": scope, "packet_id": packet_id, "source_id": source_id,
                 "observation_id": digest(key, "observation-v1", run_id, source_id, packet_id)}


def bounded_command(argv, input_data=b"", timeout=3, max_bytes=2_000_000):
    """Bound stdout BEFORE parsing; kill/reap on deadline or output overflow."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    selector = selectors.DefaultSelector()
    chunks, size, deadline = [], 0, time.monotonic() + timeout
    try:
        process.stdin.write(input_data)
        process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("command_timeout")
            if not selector.select(remaining):
                raise TimeoutError("command_timeout")
            chunk = os.read(process.stdout.fileno(), min(65536, max_bytes + 1 - size))
            if not chunk:
                selector.unregister(process.stdout)
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("command_output_limit")
            chunks.append(chunk)
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if process.returncode:
            raise OSError("command_failed")
        return b"".join(chunks)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


NUMBER = r"(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"


def parse_ss(text, key, run_id, source, limit=4096):
    """Parse iproute2 ss -HntieO, not a TCP packet parser. No JSON ss assumption.

    Missing rtt/retrans are unknown, never fabricated zeros. Kernel prints neither
    rtt=0 nor retrans=0/0; an omitted retrans token is conservatively left absent.
    """
    flows, stats = [], Counter()
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == "tcp":
            fields = fields[1:]
        if not fields:
            continue
        if fields[0] != "ESTAB":
            stats["non_established"] += 1
            continue
        if len(fields) < 5 or not fields[1].isdigit() or not fields[2].isdigit():
            stats["unparsed"] += 1
            continue
        tokens = dict(f.split(":", 1) for f in fields[5:] if ":" in f)
        cookie = tokens.get("sk", "")
        if not re.fullmatch(r"[0-9a-fA-F]+", cookie) or int(cookie, 16) == 0:
            stats["missing_socket_cookie"] += 1
            continue
        if len(flows) >= limit:
            stats["omitted"] += 1
            continue
        record = {"flow_id": digest(key, "tcp-socket-v1", run_id, source,
                                    fields[3], fields[4], cookie), "state": "ESTAB"}
        rtt = tokens.get("rtt", "")
        if re.fullmatch(NUMBER + "/" + NUMBER, rtt):
            rtt_ms, variance_ms = map(float, rtt.split("/"))
            if all(math.isfinite(v) and v >= 0 for v in (rtt_ms, variance_ms)):
                record.update(rtt_seconds=rtt_ms / 1000, rttvar_seconds=variance_ms / 1000)
        retrans = tokens.get("retrans", "")
        if re.fullmatch(r"\d+/\d+", retrans):
            current, total = map(int, retrans.split("/"))
            record.update(retrans_current=current, retrans_total_snapshot=total)
        if "rtt_seconds" not in record:
            stats["rtt_missing"] += 1
        if "retrans_total_snapshot" not in record:
            stats["retrans_missing"] += 1
        flows.append(record)
    return flows, dict(stats)


def settings(config):
    result = {name: bool(config.get(name, False)) for name in ("qfi", "tcp_flows", "packet_concordance")}
    result.update(packet_identity_key=config.get("packet_identity_key") or os.getenv("NADOR_PACKET_IDENTITY_KEY", ""),
                  packet_run_id=config.get("packet_run_id", ""),
                  packet_state_limit=config.get("packet_state_limit", 4096),
                  packet_ttl_seconds=config.get("packet_ttl_seconds", 30),
                  capture_limit=config.get("capture_limit", 8),
                  packet_interfaces=config.get("packet_interfaces", ["eth0"]),
                  packet_interval_seconds=config.get("packet_interval_seconds", 2))
    if any(result[n] for n in ("qfi", "tcp_flows", "packet_concordance")):
        if len(result["packet_identity_key"]) < 32 or not isinstance(result["packet_run_id"], str) or not 1 <= len(result["packet_run_id"]) <= 128:
            raise ValueError("explicit >=32 character packet key and nonempty run ID required")
    for name, low, high in (("packet_state_limit", 1, 65536), ("capture_limit", 1, 64)):
        if type(result[name]) is not int or not low <= result[name] <= high:
            raise ValueError("invalid " + name)
    for name, low, high in (("packet_ttl_seconds", 0.1, 300), ("packet_interval_seconds", 0.1, 30)):
        if not isinstance(result[name], (int, float)) or not math.isfinite(result[name]) or not low <= result[name] <= high:
            raise ValueError("invalid " + name)
    interfaces = result["packet_interfaces"]
    if not isinstance(interfaces, list) or not 1 <= len(interfaces) <= 4 or len(set(interfaces)) != len(interfaces) or any(not isinstance(i, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", i) for i in interfaces):
        raise ValueError("1..4 explicit interfaces required")
    return result


class Window:
    """Distinct identity concordance, NOT individual transmission/loss inference."""

    def __init__(self, limit, ttl):
        self.limit, self.ttl = limit, ttl
        self.entries = OrderedDict()
        self.stats = Counter()

    def expire(self, now):
        for identity, entry in list(self.entries.items()):
            if now - entry["first"] >= self.ttl:
                self.stats["expired_matched" if len(entry["sources"]) > 1 else "expired_unpaired"] += 1
                del self.entries[identity]

    def observe(self, observation, now):
        self.expire(now)
        identity = (observation["scope_id"], observation["packet_id"])
        if identity not in self.entries:
            if len(self.entries) >= self.limit:
                self.entries.popitem(last=False)
                self.stats["evicted"] += 1
            self.entries[identity] = {"first": now, "sources": set(), "repeats": 0}
        entry = self.entries[identity]
        source = observation["source_id"]
        if source in entry["sources"]:
            entry["repeats"] += 1
            self.stats["repeat_observations"] += 1
        elif len(entry["sources"]) < 8:
            entry["sources"].add(source)
        else:
            self.stats["source_limit"] += 1

    def report(self, now):
        self.expire(now)
        return {"semantics": "distinct_canonical_packet_identity_sets_not_loss_or_rtt",
                "window_seconds": self.ttl, "identity_limit": self.limit,
                "matched_identity_keys": sum(len(e["sources"]) > 1 for e in self.entries.values()),
                "identity_sets": [{"scope_id": scope, "packet_id": packet,
                                   "source_ids": sorted(entry["sources"]),
                                   "age_seconds": now - entry["first"],
                                   "repeat_observations": entry["repeats"]}
                                  for (scope, packet), entry in self.entries.items()],
                "evidence": dict(self.stats)}


class CaptureState:
    def __init__(self, config, source):
        self.config, self.source = settings(config), source
        self.key = self.config["packet_identity_key"].encode()
        self.counts = Counter()
        self.qfi = OrderedDict()
        self.events = []
        self.last_packet = 0

    def ingest(self, frame, point, now=None):
        now = time.monotonic() if now is None else now
        self.last_packet = time.time()
        self.counts["frames_observed"] += 1
        try:
            gtp, evidence = packet_evidence(frame, self.key, self.config["packet_run_id"], self.source + ":" + point)
        except DecodeError as exc:
            self.counts[str(exc)] += 1
            return
        self.counts["gtpu_observed"] += 1
        if self.config["qfi"]:
            label = (point, str(gtp.qfi) if gtp.qfi is not None else "unknown")
            if label not in self.qfi and len(self.qfi) >= self.config["packet_state_limit"]:
                self.qfi.popitem(last=False)
                self.counts["qfi_evicted"] += 1
            count, _ = self.qfi.pop(label, (0, now))
            self.qfi[label] = (count + 1, now)
        if self.config["packet_concordance"]:
            if len(self.events) >= self.config["packet_state_limit"]:
                self.counts["observations_omitted"] += 1
            else:
                self.events.append(evidence)

    def snapshot(self, now=None):
        now = time.monotonic() if now is None else now
        for label, (_, seen) in list(self.qfi.items()):
            if now - seen >= self.config["packet_ttl_seconds"]:
                del self.qfi[label]
        events, self.events = self.events, []
        return {"counts": dict(self.counts), "last_packet_timestamp": self.last_packet,
                "qfi": [{"point": p, "qfi": q, "packets": v[0]} for (p, q), v in self.qfi.items()],
                "observations": events}


def capture_worker(config):
    config = settings(config)
    state = CaptureState(config, config["source"])
    sockets, capability = {}, {"qfi": "disabled", "packet_concordance": "disabled", "tcp_flows": "disabled"}
    capture_error = None
    if config["qfi"] or config["packet_concordance"]:
        try:
            for interface in config["packet_interfaces"]:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                try:
                    sock.bind((interface, 0))
                    sock.setblocking(False)
                except Exception:
                    sock.close()
                    raise
                sockets[sock] = interface
            for feature in ("qfi", "packet_concordance"):
                if config[feature]:
                    capability[feature] = "available"
        except (OSError, AttributeError):
            capture_error = "af_packet_unavailable"
            for sock in sockets:
                sock.close()
            sockets.clear()
            for feature in ("qfi", "packet_concordance"):
                if config[feature]:
                    capability[feature] = "unavailable"
    selector = selectors.DefaultSelector()
    for sock in sockets:
        selector.register(sock, selectors.EVENT_READ)
    sequence, next_report = 0, time.monotonic()
    try:
        while True:
            now = time.monotonic()
            if now >= next_report:
                snapshot = state.snapshot(now)
                snapshot.update(schema=1, sequence=sequence, timestamp=time.time(), capability=dict(capability),
                                capture_error=capture_error, flows=[], tcp_evidence={})
                if config["tcp_flows"]:
                    try:
                        raw = bounded_command(["ss", "-H", "-n", "-t", "-i", "-e", "-O"], timeout=2)
                        flows, evidence = parse_ss(raw.decode("utf-8", "strict"), state.key,
                                                   config["packet_run_id"], config["source"], config["packet_state_limit"])
                        snapshot.update(flows=flows, tcp_evidence=evidence, tcp_success=True,
                                        tcp_sample_timestamp=time.time())
                        capability["tcp_flows"] = "partial" if evidence.get("unparsed") or evidence.get("missing_socket_cookie") else "available"
                    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
                        snapshot.update(tcp_success=False, tcp_evidence={"collection_failed": 1})
                        capability["tcp_flows"] = "unavailable"
                snapshot["capability"] = dict(capability)
                print(json.dumps(snapshot, separators=(",", ":")), flush=True)
                sequence += 1
                next_report = time.monotonic() + config["packet_interval_seconds"]
            ready = selector.select(max(0, min(0.2, next_report - time.monotonic())))
            for event, _ in ready:
                sock = event.fileobj
                try:
                    # recvmsg flags distinguish truncation from a complete datagram.
                    frame, _, flags, address = sock.recvmsg(65535)
                    if flags & socket.MSG_TRUNC:
                        state.counts["capture_truncated"] += 1
                        continue
                    direction = "tx" if address[2] == 4 else "rx"
                    state.ingest(frame, sockets[sock] + ":" + direction)
                except BlockingIOError:
                    pass
    finally:
        selector.close()
        for sock in sockets:
            sock.close()


class Worker:
    def __init__(self, pid, identity, config, source):
        self.pid, self.identity = str(pid), list(identity)
        self.config, self.source = config, source
        self.latest, self.received, self.failed, self.error = {}, 0, False, None
        self.lock, self.stopped = threading.Lock(), threading.Event()
        self.process = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            self.process = subprocess.Popen(["nsenter", "-t", self.pid, "-n", "python3", "/app/packet_observer.py", "--worker"],
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            child = dict(self.config, source=self.source)
            self.process.stdin.write(json.dumps(child).encode() + b"\n")
            self.process.stdin.close()
            max_line = 4096 + self.config["packet_state_limit"] * 1400
            while not self.stopped.is_set():
                line = self.process.stdout.readline(max_line + 1)
                if not line:
                    raise OSError("worker_exited")
                if len(line) > max_line or not line.endswith(b"\n"):
                    raise ValueError("worker_output_limit")
                snapshot = json.loads(line)
                if snapshot.get("schema") != 1:
                    raise ValueError("worker_schema")
                with self.lock:
                    # Queue is one snapshot; overwriting is explicit evidence.
                    omitted = self.latest.get("parent_overwrites", 0) + int(bool(self.latest.get("observations")))
                    snapshot["parent_overwrites"] = omitted
                    self.latest, self.received = snapshot, time.monotonic()
        except (OSError, ValueError):
            with self.lock:
                self.failed, self.error = True, "worker_failed"
        finally:
            if self.process:
                self.process.kill() if self.process.poll() is None else None
                self.process.wait()
                if self.process.stdout:
                    self.process.stdout.close()

    def stop(self):
        self.stopped.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self.thread.join(timeout=3)
        if self.thread.is_alive() and self.process:
            self.process.kill()
            self.thread.join(timeout=3)


class PortablePacketCapture:
    """Node integration: reconcile UID -> (PID, [node, namespace, pod, component]).

    packet_target_filter(uid, pid, identity), when supplied, is parent-only.
    collect() never executes external commands; workers refresh asynchronously.
    """

    def __init__(self, config):
        self.config = settings(config)
        self.target_filter = config.get("packet_target_filter", lambda uid, pid, identity: True)
        self.workers, self.windows, self.omitted = {}, {}, 0
        self.window = Window(self.config["packet_state_limit"] * self.config["capture_limit"], self.config["packet_ttl_seconds"])
        self.worker_factory = Worker

    def reconcile(self, active):
        enabled = any(self.config[n] for n in ("qfi", "tcp_flows", "packet_concordance"))
        candidates = []
        if enabled:
            for uid, (pid, identity) in active.items():
                if not str(pid).isdigit() or int(pid) <= 0 or len(identity) != 4:
                    raise ValueError("invalid active source")
                if self.target_filter(uid, str(pid), identity):
                    candidates.append((uid, str(pid), list(identity)))
        priority = {"upf", "gnb", "cu", "cu_up", "cu-up"}
        candidates.sort(key=lambda item: (item[2][3].lower().replace("-", "_") not in priority, item[0]))
        selected = {uid: (pid, identity) for uid, pid, identity in candidates[:self.config["capture_limit"]]}
        self.omitted = max(0, len(candidates) - len(selected))
        for uid in list(self.workers):
            worker = self.workers[uid]
            if uid not in selected or worker.pid != selected[uid][0] or worker.identity != selected[uid][1]:
                self.workers.pop(uid).stop()
                self.windows.pop(uid, None)
        for uid, (pid, identity) in selected.items():
            if uid not in self.workers:
                self.workers[uid] = self.worker_factory(pid, identity, self.config, uid)
                self.windows[uid] = Window(self.config["packet_state_limit"], self.config["packet_ttl_seconds"])

    def _drain(self, now):
        for uid, worker in self.workers.items():
            with worker.lock:
                events = worker.latest.get("observations", [])
                worker.latest["observations"] = []
                age = now - worker.received
            if worker.failed or age > self.config["packet_ttl_seconds"]:
                continue
            for event in events[:self.config["packet_state_limit"]]:
                self.windows[uid].observe(event, now)
                self.window.observe(event, now)

    def concordance_report(self):
        now = time.monotonic()
        self._drain(now)
        report = self.window.report(now)
        report["per_netns"] = {uid: window.report(now) for uid, window in self.windows.items()}
        report["omitted_sources"] = self.omitted
        return report

    def collect(self):
        from prometheus_client.core import GaugeMetricFamily
        now = time.monotonic()
        self._drain(now)
        labels = ["node", "namespace", "pod", "component"]
        specs = {
            "source_fresh": ("Worker snapshot fresh and alive; not proof of packet visibility", []),
            "snapshot_age_seconds": ("Age of last worker report", []),
            "last_packet_timestamp_seconds": ("Last frame observed, not last QFI or matched identity", []),
            "capability": ("Feature capability state; unavailable is not zero traffic", ["feature", "state"]),
            "evidence_snapshot": ("Worker-local observations; reset on worker replacement", ["reason"]),
            "qfi_packets_snapshot": ("QFI observations in TTL-bounded label state; not unique packets", ["point", "qfi"]),
            "tcp_rtt_seconds": ("Kernel TCP_INFO smoothed socket RTT; not tunnel RTT", ["flow_id"]),
            "tcp_retrans_total_snapshot": ("Kernel socket lifetime total retransmissions snapshot; not path loss", ["flow_id"]),
            "tcp_sample_timestamp_seconds": ("Timestamp of successful ss snapshot", []),
        }
        families = {name: GaugeMetricFamily("nador_portable_" + name, description, labels=labels + extra)
                    for name, (description, extra) in specs.items()}
        for worker in self.workers.values():
            with worker.lock:
                snap, received, failed = dict(worker.latest), worker.received, worker.failed
            age = now - received if received else float("inf")
            fresh = bool(received and age <= self.config["packet_ttl_seconds"] and not failed)
            identity = worker.identity
            families["source_fresh"].add_metric(identity, int(fresh))
            families["snapshot_age_seconds"].add_metric(identity, age)
            families["evidence_snapshot"].add_metric(identity + ["worker_failed"], int(failed))
            for feature in ("qfi", "tcp_flows", "packet_concordance"):
                if self.config[feature]:
                    families["capability"].add_metric(identity + [feature, snap.get("capability", {}).get(feature, "unknown") if fresh else "stale_or_failed"], 1)
            if not fresh:
                continue
            families["last_packet_timestamp_seconds"].add_metric(identity, snap.get("last_packet_timestamp", 0))
            families["evidence_snapshot"].add_metric(identity + ["parent_overwrites"], snap.get("parent_overwrites", 0))
            for reason, value in snap.get("counts", {}).items():
                families["evidence_snapshot"].add_metric(identity + [reason], value)
            for reason, value in snap.get("tcp_evidence", {}).items():
                families["evidence_snapshot"].add_metric(identity + ["tcp_" + reason], value)
            for item in snap.get("qfi", []):
                families["qfi_packets_snapshot"].add_metric(identity + [item["point"], item["qfi"]], item["packets"])
            if snap.get("tcp_success"):
                families["tcp_sample_timestamp_seconds"].add_metric(identity, snap["tcp_sample_timestamp"])
                for flow in snap.get("flows", []):
                    for field, metric in (("rtt_seconds", "tcp_rtt_seconds"), ("retrans_total_snapshot", "tcp_retrans_total_snapshot")):
                        if field in flow:
                            families[metric].add_metric(identity + [flow["flow_id"]], flow[field])
        yield from families.values()
        report = self.window.report(now)
        yield GaugeMetricFamily("nador_portable_concordance_matched_identity_keys", "Current distinct identities observed at multiple sources; not individual transmission or loss", value=report["matched_identity_keys"])
        yield GaugeMetricFamily("nador_portable_sources_omitted", "Sources omitted by capture_limit after target filter", value=self.omitted)

    def close(self):
        for worker in self.workers.values():
            worker.stop()
        self.workers.clear()
        self.windows.clear()
        self.window.entries.clear()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true", required=True)
    parser.parse_args()
    try:
        line = sys.stdin.buffer.readline(65537)
        if len(line) > 65536:
            raise ValueError("config_limit")
        capture_worker(json.loads(line))
    except (ValueError, OSError, AttributeError):
        # Never print exception text: it can contain configuration or addresses.
        print(json.dumps({"schema": 1, "fatal": "worker_start_failed"}), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
