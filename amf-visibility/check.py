"""Check read-only NGAP visibility on one AMF pod; never transmit or save packets."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess


def open_namespace(proc, uid):
    marker = "pod" + uid
    for process in proc.iterdir():
        if not process.name.isdigit():
            continue
        try:
            cgroup = process / "cgroup"
            if marker not in cgroup.read_text().replace("_", "-"):
                continue
            fd = os.open(process / "ns/net", os.O_RDONLY)
            try:
                if marker in cgroup.read_text().replace("_", "-"):
                    return fd
            except OSError:
                pass
            os.close(fd)
        except OSError:
            continue
    raise RuntimeError("target_network_namespace_not_found")


def check(uid, interface, seconds):
    fd = open_namespace(Path("/host/proc"), uid)
    try:
        prefix = ["nsenter", f"--net=/proc/self/fd/{fd}", "--"]
        subprocess.run(prefix + ["ip", "link", "show", "dev", interface],
                       pass_fds=(fd,), capture_output=True, timeout=3, check=True)
        result = subprocess.run(
            prefix + ["tshark", "-n", "-i", interface, "-f", "sctp",
                      "-Y", "ngap", "-T", "fields", "-e", "frame.number",
                      "-a", f"duration:{seconds}", "-c", "5000"],
            pass_fds=(fd,), capture_output=True, text=True, timeout=seconds + 10,
            check=True,
        )
        count = sum(line.isdigit() for line in result.stdout.splitlines())
        return {"status": "ngap_observed" if count else "capture_opened_no_ngap",
                "interface": interface, "ngap_frames": count}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pod-uid", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--seconds", type=int, default=30)
    args = parser.parse_args()
    if (not re.fullmatch(r"[0-9a-f-]{36}", args.pod_uid)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", args.interface)
            or not 5 <= args.seconds <= 120):
        parser.error("Expected a pod UID, Linux interface and 5-120 seconds")
    try:
        result = check(args.pod_uid, args.interface, args.seconds)
    except RuntimeError:
        result = {"status": "target_network_namespace_not_found"}
    except subprocess.TimeoutExpired:
        result = {"status": "capture_command_timeout"}
    except subprocess.CalledProcessError as exc:
        result = {"status": "capture_command_failed", "command": exc.cmd[3],
                  "detail": (exc.stderr or b"").decode(errors="replace")[:300]
                  if isinstance(exc.stderr, bytes) else (exc.stderr or "")[:300]}
    except OSError:
        result = {"status": "probe_tool_unavailable"}
    print(json.dumps(result))
    return 0 if result["status"] in {"ngap_observed", "capture_opened_no_ngap"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
