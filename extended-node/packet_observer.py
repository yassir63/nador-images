"""Bounded, pseudonymized TCP socket evidence from selected network namespaces."""

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import selectors
import subprocess
import sys
import threading
import time
from collections import Counter


def digest(key, *parts):
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        value = part if isinstance(part, bytes) else str(part).encode()
        mac.update(len(value).to_bytes(4, "big"))
        mac.update(value)
    return mac.hexdigest()


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
    result = {"tcp_flows": bool(config.get("tcp_flows", False))}
    result.update(packet_identity_key=config.get("packet_identity_key") or os.getenv("NADOR_PACKET_IDENTITY_KEY", ""),
                  packet_run_id=config.get("packet_run_id", ""),
                  packet_state_limit=config.get("packet_state_limit", 4096),
                  packet_ttl_seconds=config.get("packet_ttl_seconds", 30),
                  capture_limit=config.get("capture_limit", 8),
                  packet_interval_seconds=config.get("packet_interval_seconds", 2))
    if result["tcp_flows"]:
        if len(result["packet_identity_key"]) < 32 or not isinstance(result["packet_run_id"], str) or not 1 <= len(result["packet_run_id"]) <= 128:
            raise ValueError("explicit >=32 character TCP identity key and nonempty run ID required")
    for name, low, high in (("packet_state_limit", 1, 65536), ("capture_limit", 1, 64)):
        if type(result[name]) is not int or not low <= result[name] <= high:
            raise ValueError("invalid " + name)
    for name, low, high in (("packet_ttl_seconds", 0.1, 300), ("packet_interval_seconds", 0.1, 30)):
        if not isinstance(result[name], (int, float)) or not math.isfinite(result[name]) or not low <= result[name] <= high:
            raise ValueError("invalid " + name)
    return result


def capture_worker(config):
    source = config["source"]
    config = settings(config)
    key = config["packet_identity_key"].encode()
    while True:
        snapshot = {"schema": 1, "flows": []}
        try:
            raw = bounded_command(["ss", "-H", "-n", "-t", "-i", "-e", "-O"], timeout=2)
            flows, evidence = parse_ss(raw.decode("utf-8", "strict"), key,
                                       config["packet_run_id"], source, config["packet_state_limit"])
            capability = "partial" if evidence.get("unparsed") or evidence.get("missing_socket_cookie") else "available"
            snapshot.update(flows=flows, tcp_evidence=evidence, tcp_success=True,
                            tcp_sample_timestamp=time.time(), capability={"tcp_flows": capability})
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            snapshot.update(tcp_success=False, tcp_evidence={"collection_failed": 1},
                            capability={"tcp_flows": "unavailable"})
        print(json.dumps(snapshot, separators=(",", ":")), flush=True)
        time.sleep(config["packet_interval_seconds"])


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


class PortableTcpFlows:
    """Node integration: reconcile UID -> (PID, [node, namespace, pod, component]).

    packet_target_filter(uid, pid, identity), when supplied, is parent-only.
    collect() never executes external commands; workers refresh asynchronously.
    """

    def __init__(self, config):
        self.config = settings(config)
        self.target_filter = config.get("packet_target_filter", lambda uid, pid, identity: True)
        self.workers, self.omitted = {}, 0
        self.worker_factory = Worker

    def reconcile(self, active):
        candidates = []
        if self.config["tcp_flows"]:
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
        for uid, (pid, identity) in selected.items():
            if uid not in self.workers:
                self.workers[uid] = self.worker_factory(pid, identity, self.config, uid)

    def collect(self):
        from prometheus_client.core import GaugeMetricFamily
        now = time.monotonic()
        labels = ["node", "namespace", "pod", "component"]
        specs = {
            "source_fresh": ("Worker snapshot fresh and alive; not proof of TCP traffic", []),
            "snapshot_age_seconds": ("Age of last worker report", []),
            "capability": ("Feature capability state; unavailable is not zero traffic", ["feature", "state"]),
            "evidence_snapshot": ("Worker-local observations; reset on worker replacement", ["reason"]),
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
            state = snap.get("capability", {}).get("tcp_flows", "unknown") if fresh else "stale_or_failed"
            families["capability"].add_metric(identity + ["tcp_flows", state], 1)
            if not fresh:
                continue
            for reason, value in snap.get("tcp_evidence", {}).items():
                families["evidence_snapshot"].add_metric(identity + ["tcp_" + reason], value)
            if snap.get("tcp_success"):
                families["tcp_sample_timestamp_seconds"].add_metric(identity, snap["tcp_sample_timestamp"])
                for flow in snap.get("flows", []):
                    for field, metric in (("rtt_seconds", "tcp_rtt_seconds"), ("retrans_total_snapshot", "tcp_retrans_total_snapshot")):
                        if field in flow:
                            families[metric].add_metric(identity + [flow["flow_id"]], flow[field])
        yield from families.values()
        yield GaugeMetricFamily("nador_portable_sources_omitted", "Sources omitted by capture_limit after target filter", value=self.omitted)

    def close(self):
        for worker in self.workers.values():
            worker.stop()
        self.workers.clear()


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
