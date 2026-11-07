import socket
import json
import os

SOCKET_PATH = "/tmp/gtp_latency.sock"

def start_socket_listener(latency_cache):
    try:
        if os.path.exists(SOCKET_PATH):
            os.remove(SOCKET_PATH)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(SOCKET_PATH)
        print(f"[latency_socket] Listening on {SOCKET_PATH}")

        while True:
            data, _ = sock.recvfrom(1024)
            try:
                evt = json.loads(data.decode("utf-8"))
                teid = evt["teid"]
                slice = str(evt["slice"]) if "slice" in evt else "0"
                mode = str(evt.get("mode", "core"))
                kind = str(evt.get("kind", "unknown"))
                latency_cache[(teid, slice, mode, kind)] = {
                    "latency_ns": evt["latency_ns"],
                    "slice": slice,
                    "mode": mode,
                    "kind": kind,
                }
            except Exception as e:
                print("Malformed data:", e)

    except Exception as e:
        print("Socket error:", e)