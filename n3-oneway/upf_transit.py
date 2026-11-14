"""Same-host N3/N6 transit measurement for one UPF and a selected peer."""
import argparse
import collections
import json
import secrets
import signal
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from oneway import EVENT, TTL, MAX_PENDING, Pairer, slice_inventory

TRANSIT_EVENT = struct.Struct("=QQQ4sIBBB5x")


class Transit(Pairer):
    def __init__(self):
        super().__init__(0)
        self.kernel_dropped = 0

    def observe(self, event, now):
        ts, a, b, dst, teid, proto, uplink, n6 = event
        if not proto:
            self.kernel_dropped = ts
            return
        labels = {6: "tcp", 17: "udp"}[proto], "uplink" if uplink else "downlink"
        role = "n6" if n6 else "n3"
        self.events[labels, "observed_" + role] += 1
        if not now - TTL <= ts <= now:
            self.events[labels, "stale"] += 1
            return
        key = labels, a, b
        if key not in self.pending and len(self.pending) >= MAX_PENDING:
            self.events[labels, "capacity"] += 1
            return
        _, seen, _ = self.pending.setdefault(key, (now + TTL, {}, "unknown"))
        tunnel = f"{dst.hex()}:{teid:08x}"
        seen[role] = (ts, tunnel, self.slices.get(tunnel, "unknown")) if role not in seen else None

    def flush(self, now):
        for key, (deadline, seen, _) in list(self.pending.items()):
            if deadline > now:
                continue
            del self.pending[key]
            labels = key[0]
            if None in seen.values() or len(seen) != 2:
                self.events[labels, "ambiguous" if None in seen.values() else "unmatched"] += 1
                continue
            n3, tunnel, label = seen["n3"]
            n6 = seen["n6"][0]
            delay = n6 - n3 if labels[1] == "uplink" else n3 - n6
            if not 0 <= delay <= TTL:
                self.events[labels, "invalid_delay"] += 1
                continue
            if self.slices.get(tunnel, "unknown") != label:
                label = "unknown"
            self.record(labels, label, delay / 1e9)

    def render(self):
        return super().render().replace(b"nador_n3_oneway_", b"nador_upf_transit_") + (
            f"nador_upf_transit_bpf_events_dropped_total {self.kernel_dropped}\n".encode()
        )


def main():
    cli = argparse.ArgumentParser()
    for name in ("gnb", "upf", "peer", "n3", "n6", "mapper-url"):
        cli.add_argument("--" + name, required=True)
    cli.add_argument("--pid", type=int, required=True)
    cli.add_argument("--port", type=int, required=True, help="Transport port on the remote peer")
    cli.add_argument("--sample", type=int, default=16)
    cli.add_argument("--metrics-port", type=int, default=55437)
    cli.add_argument("--bind", default="127.0.0.1")
    cli.add_argument("--observer", default="nador-n3-observer")
    args = cli.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.sample <= 0xffffffff or args.pid < 1:
        cli.error("invalid port, sample factor or PID")
    for addr in (args.gnb, args.upf, args.peer):
        socket.inet_pton(socket.AF_INET, addr)
    collector = Transit()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return
            with lock:
                data = collector.render()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def maintenance():
        while True:
            with lock:
                collector.flush(time.monotonic_ns())
            time.sleep(.2)

    def refresh():
        while True:
            try:
                with urllib.request.urlopen(args.mapper_url.rstrip("/") + "/inventory/ues?limit=2000", timeout=2) as res:
                    mapping = slice_inventory(json.load(res)["ues"])
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                mapping = {}
            with lock:
                collector.slices = mapping
            time.sleep(1)

    def stop(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    server = ThreadingHTTPServer((args.bind, args.metrics_port), Handler)
    for target in (server.serve_forever, maintenance, refresh):
        threading.Thread(target=target, daemon=True).start()
    proc = subprocess.Popen(
        ["nsenter", "-t", str(args.pid), "-n", args.observer, args.n3, args.gnb, args.upf,
         str(args.port), str(args.sample), secrets.token_hex(8), secrets.token_hex(8),
         args.n6, args.peer], stdout=subprocess.PIPE,
    )
    try:
        while data := proc.stdout.read(EVENT.size):
            with lock:
                collector.observe(TRANSIT_EVENT.unpack(data), time.monotonic_ns())
        raise RuntimeError(f"UPF observer exited: {proc.wait()}")
    finally:
        proc.terminate()
        proc.wait(timeout=3)
        server.server_close()


if __name__ == "__main__":
    main()
