"""Experimental live N3 transit measurements from TC eBPF observations."""

import argparse
import collections
import hashlib
import hmac
import json
import math
import os
import queue
import re
import signal
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NS = 10**9
TTL = 3 * NS
MAX_PENDING = 16384
LABELS = (("tcp", "uplink"), ("tcp", "downlink"), ("udp", "uplink"), ("udp", "downlink"))
BUCKETS = (.0001, .00025, .0005, .001, .0025, .005, .01, .025, .05, .1, .25, 1)
EVENT = struct.Struct("=QQQ4sIBB6x")
TUNNEL = re.compile(r"[0-9a-f]{8}:[0-9a-f]{8}")
SLICE = re.compile(r"[0-9a-f]{2}:[0-9a-f]{6}")


def slice_inventory(rows):
    mapping = {}
    for row in rows:
        label = row.get("slice_id")
        if not isinstance(label, str) or not SLICE.fullmatch(label):
            continue
        for side, endpoint in (("ul", "upf_n3_ip"), ("dl", "gnb_n3_ip")):
            try:
                ip = socket.inet_pton(socket.AF_INET, row.get(endpoint) or "")
                teid = int(row.get(side + "_teid") or "", 16)
                if not 0 < teid <= 0xffffffff:
                    continue
            except (OSError, ValueError, TypeError):
                continue
            key = f"{ip.hex()}:{teid:08x}"
            mapping[key] = label if mapping.get(key, label) == label else "unknown"
    return mapping


def clock_interval(t1, t2, t3, t4):
    """Collector minus observer clock, assuming nonnegative transit in both directions."""
    if t4 < t1 or t3 < t2 or t3-t4 > t2-t1:
        raise ValueError("invalid clock exchange")
    return t3-t4, t2-t1


class Pairer:
    def __init__(self, budget, sample_log=None):
        self.budget = budget
        self.pending = {}
        self.events = collections.Counter()
        self.clock = {}
        self.hist = {k: [0] * (len(BUCKETS)+1) for k in LABELS}
        self.total = collections.Counter()
        self.slices = {}
        self.slice_hist = {}
        self.slice_total = collections.Counter()
        self.sample_log = sample_log
        self.sample_log_dropped = 0

    def ingest(self, role, rows, now):
        for identity, protocol, direction, ts, err, tunnel in rows:
            labels = protocol, direction
            if labels not in self.hist or not re.fullmatch("[0-9a-f]{32}", identity):
                continue
            self.events[labels, "observed_" + role] += 1
            if not 0 <= err <= self.budget or not now-TTL <= ts <= now+self.budget:
                self.events[labels, "invalid_clock"] += 1
                continue
            key = labels, identity, tunnel
            if key not in self.pending and len(self.pending) >= MAX_PENDING:
                self.events[labels, "capacity"] += 1
                continue
            deadline, seen, _ = self.pending.setdefault(key, (now+TTL, {}, self.slices.get(tunnel, "unknown")))
            seen[role] = (ts, err) if role not in seen else None

    def flush(self, now):
        for key, (deadline, seen, slice_id) in list(self.pending.items()):
            if deadline > now:
                continue
            del self.pending[key]
            labels, _, tunnel = key
            if len(seen) != 2 or not all(seen.values()):
                self.events[labels, "ambiguous" if None in seen.values() else "unmatched"] += 1
                continue
            src, dst = ("gnb", "upf") if labels[1] == "uplink" else ("upf", "gnb")
            delay_ns = seen[dst][0] - seen[src][0]
            uncertainty_ns = seen["gnb"][1] + seen["upf"][1]
            if uncertainty_ns > self.budget:
                self.events[labels, "uncertain_pair"] += 1
                continue
            if delay_ns < 0:
                self.events[labels, "negative_delay"] += 1
                continue
            if self.slices.get(tunnel, "unknown") != slice_id:
                slice_id = "unknown"
            self.record(labels, slice_id, delay_ns / NS)
            if self.sample_log is not None:
                try:
                    self.sample_log.put_nowait({
                        "event": "nador_n3_oneway_sample",
                        "protocol": labels[0],
                        "direction": labels[1],
                        "slice": slice_id,
                        "receive_timestamp_ns": seen[dst][0],
                        "delay_ns": delay_ns,
                        "clock_uncertainty_ns": uncertainty_ns,
                        "gnb_clock_uncertainty_ns": seen["gnb"][1],
                        "upf_clock_uncertainty_ns": seen["upf"][1],
                    })
                except queue.Full:
                    self.sample_log_dropped += 1

    def record(self, labels, slice_id, delay):
        self.events[labels, "matched"] += 1
        self.total[labels] += delay
        skey = (*labels, slice_id)
        if skey not in self.slice_hist and len(self.slice_hist) >= 256:
            skey = (*labels, "unknown")
        slice_buckets = self.slice_hist.setdefault(skey, [0] * (len(BUCKETS)+1))
        self.slice_total[skey] += delay
        for i, bound in enumerate((*BUCKETS, math.inf)):
            if delay <= bound:
                self.hist[labels][i] += 1
                slice_buckets[i] += 1

    def render(self):
        out = ["# TYPE nador_n3_oneway_seconds histogram", "# TYPE nador_n3_oneway_observations_total counter"]
        for (p, d), buckets in self.hist.items():
            l = f'protocol="{p}",direction="{d}"'
            for bound, count in zip((*BUCKETS, "+Inf"), buckets):
                out.append(f'nador_n3_oneway_seconds_bucket{{{l},le="{bound}"}} {count}')
            out += [f'nador_n3_oneway_seconds_count{{{l}}} {buckets[-1]}',
                    f'nador_n3_oneway_seconds_sum{{{l}}} {self.total[p,d]}']
        for ((p, d), outcome), count in sorted(self.events.items()):
            out.append(f'nador_n3_oneway_observations_total{{protocol="{p}",direction="{d}",outcome="{outcome}"}} {count}')
        out.append("# TYPE nador_n3_oneway_slice_seconds histogram")
        for (p, d, sid), buckets in sorted(self.slice_hist.items()):
            l = f'protocol="{p}",direction="{d}",slice="{sid}"'
            for bound, count in zip((*BUCKETS, "+Inf"), buckets):
                out.append(f'nador_n3_oneway_slice_seconds_bucket{{{l},le="{bound}"}} {count}')
            out += [f'nador_n3_oneway_slice_seconds_count{{{l}}} {buckets[-1]}',
                    f'nador_n3_oneway_slice_seconds_sum{{{l}}} {self.slice_total[p,d,sid]}']
        for role, (err, stamp, dropped, kernel_dropped) in sorted(self.clock.items()):
            out += [f'nador_n3_oneway_clock_uncertainty_seconds{{anchor="{role}"}} {err/NS}',
                    f'nador_n3_oneway_calibration_timestamp_seconds{{anchor="{role}"}} {stamp/NS}',
                    f'nador_n3_oneway_agent_queue_dropped_total{{anchor="{role}"}} {dropped}',
                    f'nador_n3_oneway_bpf_events_dropped_total{{anchor="{role}"}} {kernel_dropped}']
        if self.sample_log is not None:
            out += ["# TYPE nador_n3_oneway_sample_log_dropped_total counter",
                    f"nador_n3_oneway_sample_log_dropped_total {self.sample_log_dropped}"]
        return ("\n".join(out)+"\n").encode()


def serve(args, token):
    sample_log = queue.Queue(maxsize=4096) if args.log_samples else None
    pairer = Pairer(int(args.max_uncertainty_ms*1e6), sample_log)
    lock = threading.Lock()
    key = bytes.fromhex(token)
    clock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clock.bind((args.bind, args.port))

    def write_samples():
        while True:
            print(json.dumps(sample_log.get(), separators=(",", ":")), flush=True)

    if sample_log is not None:
        threading.Thread(target=write_samples, daemon=True).start()

    def clock_server():
        while True:
            data, peer = clock.recvfrom(64)
            t2 = time.time_ns()
            if len(data) == 48 and hmac.compare_digest(data[16:], hmac.digest(key, data[:16], "sha256")):
                reply = data[:16] + struct.pack("!QQ", t2, time.time_ns())
                try:
                    clock.sendto(reply + hmac.digest(key, reply, "sha256"), peer)
                except OSError:
                    continue

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(3)
            super().setup()

        def reply(self, body, kind="application/json"):
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/metrics":
                with lock:
                    body = pairer.render()
                self.reply(body, "text/plain; version=0.0.4")
            else:
                self.send_error(404)

        def authorized(self):
            return hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer "+token)

        def do_POST(self):
            if self.path != "/observations" or not self.authorized():
                self.send_error(403)
                return
            try:
                size = int(self.headers["Content-Length"])
                if not 0 < size <= 65536:
                    raise ValueError
                role, rows, quality = json.loads(self.rfile.read(size))
                if role not in ("gnb", "upf") or len(rows) > 256 or len(quality) != 4:
                    raise ValueError
                if not all(type(x) is int and x >= 0 for x in quality):
                    raise ValueError
                for identity, protocol, direction, ts, err, tunnel in rows:
                    if (not all(type(x) is str for x in (identity, protocol, direction, tunnel))
                        or type(ts) is not int or type(err) is not int or not TUNNEL.fullmatch(tunnel)):
                        raise ValueError
                with lock:
                    pairer.ingest(role, rows, time.time_ns())
                    pairer.clock[role] = quality
            except (ValueError, KeyError, TypeError):
                self.send_error(400)
                return
            self.reply(b"{}")

        def log_message(self, *_):
            pass

    def expire():
        while True:
            time.sleep(.2)
            with lock:
                pairer.flush(time.time_ns())

    def refresh_slices():
        while True:
            try:
                with urllib.request.urlopen(args.mapper_url.rstrip("/") + "/inventory/ues?limit=2000", timeout=2) as res:
                    mapping = slice_inventory(json.load(res)["ues"])
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                mapping = {}
            with lock:
                pairer.slices = mapping
            time.sleep(1)

    threading.Thread(target=expire, daemon=True).start()
    threading.Thread(target=clock_server, daemon=True).start()
    threading.Thread(target=refresh_slices, daemon=True).start()
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()


def agent(args, token):
    events = queue.Queue(maxsize=4096)
    dropped = 0
    kernel_dropped = 0
    failures = []

    def request(path, data=None):
        req = urllib.request.Request(args.url+path, data=data, headers={"Authorization": "Bearer "+token})
        with urllib.request.urlopen(req, timeout=1) as res:
            return json.load(res)

    def reader():
        nonlocal dropped, kernel_dropped
        try:
            while data := capture.stdout.read(EVENT.size):
                ts, a, b, dst, teid, proto, uplink = EVENT.unpack(data)
                if not proto:
                    kernel_dropped = ts
                    continue
                direction = "uplink" if uplink else "downlink"
                try:
                    events.put_nowait((f"{a:016x}{b:016x}", {6: "tcp", 17: "udp"}[proto],
                                       direction, ts, f"{dst.hex()}:{teid:08x}"))
                except queue.Full:
                    dropped += 1
        except (ValueError, KeyError, struct.error) as exc:
            failures.append(exc)

    key = hashlib.sha256(b"nador-n3-observer" + bytes.fromhex(token)).hexdigest()
    clock_key = bytes.fromhex(token)
    endpoint = urlsplit(args.url)
    clock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clock.connect((endpoint.hostname, endpoint.port or args.port))
    clock.settimeout(.15)
    capture = subprocess.Popen(
        (["nsenter", "-t", str(args.pid), "-n"] if args.pid else []) +
        [args.observer, args.interface, args.gnb, args.upf, str(args.test_port),
         str(args.sample), key[:16], key[16:32]],
        stdout=subprocess.PIPE,
    )
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    samples = collections.deque(maxlen=8)
    last_cal = 0
    epoch = time.time_ns()-time.monotonic_ns()
    try:
        while capture.poll() is None and not failures:
            mono = time.monotonic_ns()
            if mono-last_cal >= NS//4:
                try:
                    nonce = os.urandom(16)
                    probe = nonce + hmac.digest(clock_key, nonce, "sha256")
                    t1 = time.time_ns()
                    clock.send(probe)
                    reply = clock.recv(64)
                    t4 = time.time_ns()
                    if len(reply) != 64 or reply[:16] != nonce or not hmac.compare_digest(
                        reply[32:], hmac.digest(clock_key, reply[:32], "sha256")
                    ):
                        raise ValueError("invalid clock reply")
                    t2, t3 = struct.unpack("!QQ", reply[16:32])
                    bracket = clock_interval(t1, t2, t3, t4)
                    new_epoch = t4-time.monotonic_ns()
                    if abs(new_epoch-epoch) > 200_000:
                        samples.clear()
                        while not events.empty():
                            events.get_nowait()
                    epoch = new_epoch
                    samples.append((t4, *bracket))
                except (OSError, ValueError):
                    pass
                last_cal = mono
            now = time.time_ns()
            fresh = [(stamp, lo, hi) for stamp,lo,hi in samples if 0 <= now-stamp < NS]
            batch = []
            if len(fresh) >= 2:
                # Widen brackets for clock drift; never treat this as a hard bound.
                lo = max(a-(now-t+NS//4)//1000 for t,a,b in fresh)
                hi = min(b+(now-t+NS//4)//1000 for t,a,b in fresh)
                if lo <= hi:
                    while len(batch) < 256 and not events.empty():
                        identity, proto, direction, ts, tunnel = events.get_nowait()
                        ts += epoch
                        if ts >= fresh[0][0]-NS//4:
                            batch.append([identity, proto, direction, ts+(lo+hi)//2, (hi-lo+1)//2, tunnel])
                    if batch or mono == last_cal:
                        try:
                            request("/observations", json.dumps([args.role, batch, [(hi-lo+1)//2, fresh[-1][0]+(lo+hi)//2, dropped, kernel_dropped]]).encode())
                        except OSError:
                            dropped += len(batch)
            time.sleep(.02)
        raise RuntimeError(f"capture stopped: {failures or capture.returncode}")
    finally:
        clock.close()
        capture.terminate()
        try:
            capture.wait(timeout=2)
        except subprocess.TimeoutExpired:
            capture.kill()
            capture.wait()


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("mode", choices=("collector", "agent"))
    cli.add_argument("--bind", default="0.0.0.0")
    cli.add_argument("--port", type=int, default=55393)
    cli.add_argument("--max-uncertainty-ms", type=float, default=2)
    cli.add_argument("--log-samples", action="store_true",
                     help="Collector only: emit each accepted N3 measurement as JSON to stdout")
    cli.add_argument("--url")
    cli.add_argument("--mapper-url")
    cli.add_argument("--observer", default="nador-n3-observer")
    cli.add_argument("--role", choices=("gnb", "upf"))
    cli.add_argument("--gnb")
    cli.add_argument("--upf")
    cli.add_argument("--interface", default="eth0")
    cli.add_argument("--pid", type=int)
    cli.add_argument("--test-port", type=int, default=0)
    cli.add_argument("--sample", type=int, default=16)
    args = cli.parse_args()
    token = os.environ.get("NADOR_ONEWAY_TOKEN", "")
    if not re.fullmatch("[0-9a-f]{64}", token):
        cli.error("NADOR_ONEWAY_TOKEN must be 32 random bytes encoded as hex")
    if not 1 <= args.sample <= 0xffffffff or not 0 <= args.test_port <= 65535 or (args.mode == "agent" and not all((args.url, args.role, args.gnb, args.upf))):
        cli.error("agent needs URL, role, gNB and UPF addresses; sample must be positive")
    if args.mode == "collector" and not args.mapper_url:
        cli.error("collector needs --mapper-url")
    if args.log_samples and args.mode != "collector":
        cli.error("--log-samples is only available on the collector")
    def stop(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    (serve if args.mode == "collector" else agent)(args, token)


if __name__ == "__main__":
    main()
