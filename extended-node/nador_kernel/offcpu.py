"""Targeted completed off-CPU intervals, partitioned by switch-out state.

These are live-generation snapshots, NOT pod-lifetime counters, wakeup latency,
or exact sleep time. See README.md for identity and accounting limitations.
"""

import ctypes as ct
import os
import re
import time
from pathlib import Path

from .common import Source, bounded_size, read_diagnostics, trace_format
from .procfs import discover_tasks

DIAGNOSTICS = ("events", "map_failures", "identity_mismatches", "exits",
               "unknown_states", "clock_errors", "discarded_pending",
               "stack_errors", "stack_map_failures")


def state_masks(format_text):
    """Accept numeric kernel tracefs masks only; never guess a preemption bit."""
    match = re.search(r'prev_state\s*&\s*(0[xX][0-9a-fA-F]+|[0-9]+)\s*\)?\s*\?\s*"\+"', format_text)
    if not match:
        raise ValueError("cannot determine sched_switch preemption marker")
    preempt = int(match.group(1), 0)
    flags = re.findall(r'\{\s*(0[xX][0-9a-fA-F]+|[0-9]+)\s*,\s*"[SDTtXZPI]"\s*\}', format_text)
    blocked = 0
    for flag in flags:
        blocked |= int(flag, 0)
    if preempt <= 0 or preempt & (preempt - 1) or not blocked or blocked >= preempt:
        raise ValueError("unsupported sched_switch state masks")
    return preempt, blocked


def classify_state(state, preempt, blocked):
    if state in (0, preempt):
        return "runnable"
    if state > 0 and not state & ~blocked:
        return "blocked"
    return "unknown"


class OffCPU(Source):
    def __init__(self, enabled=False, max_targets=4096, *, bpf_factory=None,
                 tracefs_root=None, clock_ticks=None, off_cpu_stacks=False,
                 max_stacks=1024, max_stack_keys=8192):
        super().__init__(enabled)
        self.max_targets = bounded_size(max_targets)
        self.stack_sampling = bool(off_cpu_stacks)
        self.max_stacks = bounded_size(max_stacks)
        self.max_stack_keys = bounded_size(max_stack_keys)
        self.targets = {}
        self.generation = 0
        self.pods = {}
        self.discovery = {"complete": False, "errors": ["not reconciled"]}
        if not self.enabled:
            return
        try:
            fmt, path = trace_format("sched:sched_switch", tracefs_root)
            preempt, blocked = state_masks(fmt)
            _, exit_path = trace_format("sched:sched_process_exit", tracefs_root)
            ticks = os.sysconf("SC_CLK_TCK") if clock_ticks is None else clock_ticks
            if isinstance(ticks, bool) or not isinstance(ticks, int) or ticks <= 0 or 10**9 % ticks:
                raise ValueError("unsupported proc USER_HZ")
            source = (Path(__file__).parent / "bpf/offcpu.c").read_text()
            for token, value in {"@CAPACITY@": self.max_targets, "@PREEMPT@": preempt,
                                 "@BLOCKED@": blocked, "@TICK_NS@": 10**9 // ticks,
                                 "@STACKS@": int(self.stack_sampling),
                                 "@STACK_CAPACITY@": self.max_stacks,
                                 "@STACK_KEY_CAPACITY@": self.max_stack_keys}.items():
                source = source.replace(token, str(value))
            self.evidence.update(preemption_mask=preempt, blocked_mask=blocked,
                                 user_hz=ticks, format_paths=[path, exit_path],
                                 off_cpu_stacks=self.stack_sampling,
                                 identity="host TGID/TID + proc start ticks + bound kernel start_boottime ns")
            self.load(source, ("sched:sched_switch", "sched:sched_process_exit"), bpf_factory)
        except Exception as exc:
            self.error("capability", exc)

    def _remove(self, tid, generation):
        target_map = self.bpf["targets"]
        try:
            del target_map[target_map.Key(tid)]
        except KeyError:
            pass
        for name in ("starts", "pending", "totals", "exited"):
            table = self.bpf[name]
            try:
                del table[table.Key(tid=tid, generation=generation)]
            except KeyError:
                pass
        if self.stack_sampling:
            table = self.bpf["blocked_stacks"]
            for key, _ in list(table.items()):
                if int(key.tid) == tid and int(key.generation) == generation:
                    try:
                        del table[key]
                    except KeyError:
                        pass

    def _prune(self):
        # An in-flight old-generation handler can insert after removal. Reap it
        # at the next refresh rather than leaking capacity across PID churn.
        live = {(tid, value[3]) for tid, value in self.targets.items()}
        names = ["starts", "pending", "totals", "exited"]
        if self.stack_sampling:
            names.append("blocked_stacks")
        for name in names:
            table = self.bpf[name]
            for key, _ in list(table.items()):
                if (int(key.tid), int(key.generation)) not in live:
                    try:
                        del table[key]
                    except KeyError:
                        pass

    def reconcile(self, processes, pods, proc_root, node):
        """Refresh explicit host TIDs and their generations; failures revoke targets."""
        self.node, self.pods = node, dict(pods)
        wanted, self.discovery = discover_tasks(processes, pods, proc_root, self.max_targets)
        if self.bpf is None:
            return self.discovery
        try:
            for tid, old in list(self.targets.items()):
                if wanted.get(tid) != old[:3]:
                    self._remove(tid, old[3])
                    del self.targets[tid]
            for tid, identity in wanted.items():
                if tid in self.targets:
                    continue
                self.generation += 1
                table = self.bpf["targets"]
                uid, tgid, start = identity
                table[table.Key(tid)] = table.Leaf(
                    tgid=tgid, start_ticks=start, generation=self.generation, kernel_start_ns=0)
                self.targets[tid] = (*identity, self.generation)
            self._prune()
        except Exception as exc:
            self.error("reconcile", exc)
            self.discovery["complete"] = False
            # A partial map refresh must not continue tracing stale ownership.
            self._cleanup()
            self.targets.clear()
        return self.discovery

    def snapshot(self):
        diagnostics, totals, stack_counts, read_ok = {}, {}, [], True
        if self.bpf is not None:
            try:
                diagnostics = read_diagnostics(self.bpf, DIAGNOSTICS)
                totals = {(int(k.tid), int(k.generation)): v
                          for k, v in self.bpf["totals"].items()}
                if self.stack_sampling:
                    stack_counts = list(self.bpf["blocked_stacks"].items())
            except Exception as exc:
                self.error("snapshot", exc)
                read_ok = False
        status = self.status(diagnostics, read_ok)
        tasks = []
        for tid, (uid, tgid, start, generation) in sorted(self.targets.items()):
            value = totals.get((tid, generation)) if status["available"] else None
            tasks.append({
                "uid": uid, "pod": list(self.pods[uid]), "tid": tid, "tgid": tgid,
                "start_ticks": start, "generation": generation,
                "runnable_ns": None if value is None else int(value.runnable_ns),
                "blocked_ns": None if value is None else int(value.blocked_ns),
                "unknown_ns": None if value is None else int(value.unknown_ns),
                "completed_intervals": None if value is None else int(value.samples),
            })
        stacks = []
        if status["available"]:
            for key, value in stack_counts:
                tid, generation = int(key.tid), int(key.generation)
                current = self.targets.get(tid)
                if current is not None and current[3] == generation:
                    stacks.append({"tid": tid, "generation": generation, "uid": current[0],
                                   "stack_id": int(key.stack_id), "samples": int(value.value)})
        return {"node": self.node, "monotonic_ns": time.monotonic_ns(),
                "status": status, "discovery": self.discovery, "tasks": tasks,
                "stack_sampling": {"enabled": self.stack_sampling, "decoded": False,
                                   "max_stacks": self.max_stacks,
                                   "max_stack_keys": self.max_stack_keys},
                "blocked_stacks": sorted(stacks, key=lambda row: (row["tid"], row["stack_id"]))}
