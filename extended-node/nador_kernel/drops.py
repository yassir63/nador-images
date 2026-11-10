"""Kernel-local skb free reason counts by device namespace and interface.

Pod ownership is attached only to sampling-window deltas with stable discovery,
never retroactively to raw lifetime totals. No current-task attribution is used.
"""

import time
from pathlib import Path

from .common import Source, bounded_size, read_diagnostics, trace_format
from .procfs import namespace_index

DIAGNOSTICS = ("events", "map_failures")
LOCATIONS = {0: "device_namespace", 1: "missing_skb", 2: "missing_dev",
             3: "missing_ifindex", 4: "missing_netns", 5: "read_error"}


class AttributedDrops(Source):
    def __init__(self, enabled=False, max_keys=8192, *, bpf_factory=None, tracefs_root=None):
        super().__init__(enabled)
        self.max_keys = bounded_size(max_keys)
        self.pods = {}
        self.index = {"owners": {}, "host_inode": None, "complete": False,
                      "errors": ["not reconciled"]}
        self._baseline_index = None
        self._changed = set()
        self._incomplete_window = True
        self._previous = None
        if not self.enabled:
            return
        try:
            fmt, path = trace_format("skb:kfree_skb", tracefs_root)
            # Old kernels have kfree_skb without a reason field. Do not fake codes.
            import re
            if not re.search(r"field:[^;]*\breason\s*;", fmt) or not re.search(r"field:[^;]*\bskbaddr\s*;", fmt):
                raise ValueError("kfree_skb requires skbaddr and reason fields")
            source = (Path(__file__).parent / "bpf/drops.c").read_text()
            source = source.replace("@CAPACITY@", str(self.max_keys))
            self.evidence.update(format_paths=[path], reason_codes="numeric, kernel-local, unclamped",
                                 attribution="skb->dev->nd_net.net->ns.inum + skb->dev->ifindex")
            self.load(source, ("skb:kfree_skb",), bpf_factory)
        except Exception as exc:
            self.error("capability", exc)

    def reconcile(self, processes, pods, proc_root, node):
        """Read namespace inode ownership from os.stat(PID/ns/net).st_ino."""
        self.node, self.pods = node, dict(pods)
        fresh = namespace_index(processes, pods, proc_root)
        for inode in set(self.index["owners"]) | set(fresh["owners"]):
            if self.index["owners"].get(inode) != fresh["owners"].get(inode):
                self._changed.add(inode)
        if not fresh["complete"] or not self.index["complete"]:
            self._incomplete_window = True
        if fresh["host_inode"] != self.index["host_inode"]:
            self._incomplete_window = True
        self.index = fresh
        return fresh

    def _ownership(self, inode, location):
        candidates = list(self.index["owners"].get(inode, ()))
        if location != 0:
            return "unattributed", LOCATIONS.get(location, "unknown_location"), candidates, None
        if inode == self.index["host_inode"]:
            return "ambiguous", "host_namespace", candidates, None
        if len(candidates) > 1:
            return "ambiguous", "shared_namespace", candidates, None
        if self._baseline_index is None:
            return "unattributed", "no_window_baseline", candidates, None
        if self._incomplete_window or not self.index["complete"]:
            return "unattributed", "incomplete_discovery", candidates, None
        if inode in self._changed or self._baseline_index["owners"].get(inode, ()) != tuple(candidates):
            return "unattributed", "ownership_changed", candidates, None
        if len(candidates) == 1:
            return "unique_in_inventory", "stable_inventory", candidates, candidates[0]
        return "unattributed", "namespace_not_in_inventory", candidates, None

    def snapshot(self):
        diagnostics, raw, records, read_ok = {}, {}, [], True
        if self.bpf is not None:
            try:
                diagnostics = read_diagnostics(self.bpf, DIAGNOSTICS)
                raw = {(int(k.netns), int(k.ifindex), int(k.reason), int(k.location)): int(v.value)
                       for k, v in self.bpf["counts"].items()}
            except Exception as exc:
                self.error("snapshot", exc)
                read_ok = False
        status = self.status(diagnostics, read_ok)
        if status["available"]:
            for key, count in sorted(raw.items()):
                inode, ifindex, reason, location = key
                previous = 0 if self._previous is None else self._previous.get(key, 0)
                delta = count - previous if count >= previous else None
                ownership, why, candidates, uid = self._ownership(inode, location)
                records.append({
                    "netns_inode": inode or None, "ifindex": ifindex or None,
                    "reason_code": reason, "location": LOCATIONS.get(location, "unknown_location"),
                    "raw_count": count, "window_count": delta,
                    "ownership": ownership, "ownership_reason": why,
                    "candidate_uids": candidates, "uid": uid,
                    "pod": list(self.pods[uid]) if uid is not None else None,
                })
        if self.bpf is not None and read_ok:
            self._previous = raw
            self._baseline_index = self.index
            self._changed.clear()
            self._incomplete_window = not self.index["complete"]
        elif not read_ok:
            # The next successful interval spans an unknown discovery period.
            self._baseline_index = None
            self._incomplete_window = True
        return {"node": self.node, "monotonic_ns": time.monotonic_ns(),
                "status": status, "namespace_discovery": self.index,
                "records": records}
