"""Resolve one container to its network namespace without mounting a runtime socket."""
import os
import re
import sys
from pathlib import Path


def find_pid(container_id, proc=Path("/proc")):
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise ValueError("Expected a full container ID")
    pids = []
    pattern = re.compile(rf"(?:/|[-]){container_id}(?:\.scope)?(?:/|$)")
    for path in proc.iterdir():
        if not path.name.isdecimal():
            continue
        try:
            cgroups = (path / "cgroup").read_text().splitlines()
            if any(pattern.search(row) for row in cgroups):
                pids.append(int(path.name))
        except (OSError, UnicodeError):
            continue
    if not pids:
        raise RuntimeError(f"No live process found for container {container_id}")
    return min(pids)


if __name__ == "__main__":
    pid = find_pid(sys.argv[1])
    os.execv(sys.executable, [sys.executable, *sys.argv[2:], "--pid", str(pid)])
