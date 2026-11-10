"""Read-only host proc helpers; no commands, setns, sysctls, or PID inference."""

import os
from pathlib import Path


def process_path(process, proc_root):
    path, root = Path(process), Path(proc_root)
    if not path.name.isdecimal() or int(path.name) <= 0 or path.parent != root:
        raise ValueError("process must be a numeric PID directly beneath proc_root")
    return path


def task_stat(path):
    text = Path(path).read_text()
    left = text.index("(")
    right = text.rindex(")")
    tid = int(text[:left].strip())
    fields = text[right + 1:].split()
    return tid, fields[0], int(fields[19])


def discover_tasks(processes, pods, proc_root, limit):
    tasks, errors = {}, []
    complete, omitted = True, 0
    for uid, process in processes:
        try:
            if uid not in pods:
                raise ValueError("process UID absent from pods inventory")
            path = process_path(process, proc_root)
            pid, state, leader_start = task_stat(path / "stat")
            if pid != int(path.name) or state in ("Z", "X", "x"):
                raise ValueError("leader identity is invalid or exited")
            found = {}
            for task in (path / "task").iterdir():
                if not task.name.isdecimal():
                    continue
                try:
                    tid, state, start = task_stat(task / "stat")
                    if tid != int(task.name):
                        raise ValueError("thread identity changed")
                    if state not in ("Z", "X", "x"):
                        found[tid] = (uid, pid, start)
                except (OSError, ValueError, IndexError) as exc:
                    complete = False
                    errors.append(str(exc))
            if task_stat(path / "stat")[2] != leader_start:
                raise ValueError("leader was reused during discovery")
            for tid, identity in found.items():
                if tid in tasks and tasks[tid] != identity:
                    raise ValueError("conflicting thread ownership")
                if len(tasks) >= limit and tid not in tasks:
                    complete = False
                    omitted += 1
                else:
                    tasks[tid] = identity
        except (OSError, ValueError, IndexError) as exc:
            complete = False
            errors.append(str(exc))
    return tasks, {"complete": complete, "omitted_threads": omitted, "errors": errors[:32]}


def namespace_index(processes, pods, proc_root):
    owners, errors = {}, []
    complete = True
    host_inode = None
    try:
        host_inode = os.stat(Path(proc_root) / "1/ns/net").st_ino
    except OSError as exc:
        complete = False
        errors.append("host namespace unknown: " + str(exc))
    for uid, process in processes:
        try:
            if uid not in pods:
                raise ValueError("process UID absent from pods inventory")
            path = process_path(process, proc_root)
            before = task_stat(path / "stat")
            inode = os.stat(path / "ns/net").st_ino
            if task_stat(path / "stat") != before:
                raise ValueError("process changed during namespace discovery")
            owners.setdefault(inode, set()).add(uid)
        except (OSError, ValueError, IndexError) as exc:
            complete = False
            errors.append(str(exc))
    return {
        "owners": {inode: tuple(sorted(uids)) for inode, uids in owners.items()},
        "host_inode": host_inode,
        "complete": complete,
        "errors": errors[:32],
    }
